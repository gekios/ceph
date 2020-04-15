'''
Task that deploys a Ceph cluster on all the nodes
using Ceph-salt
Linter:
    flake8 --max-line-length=100
'''
import logging
import time
import yaml
import argparse
import uuid

from salt_manager import SaltManager
from scripts import Scripts
from teuthology import misc
from util import (
    copy_directory_recursively,
    enumerate_osds,
    get_remote_for_role,
    get_rpm_pkg_version,
    introspect_roles,
    remote_exec,
    remote_run_script_as_root,
    sudo_append_to_file,
    )

from teuthology.exceptions import (
    CommandFailedError,
    ConfigError,
    )
from teuthology.orchestra import run
from teuthology.task import Task
from teuthology.contextutil import safe_while
from teuthology.orchestra.daemon import DaemonGroup

log = logging.getLogger(__name__)
ceph_salt_ctx = {}
reboot_tries = 50

def anchored(log_message):
    global ceph_salt_ctx
    assert 'log_anchor' in ceph_salt_ctx, "ceph_salt_ctx not populated"
    return "{}{}".format(ceph_salt_ctx['log_anchor'], log_message)


class CephSalt(Task):
    """
    Deploy a Ceph cluster on all remotes using
    Ceph-salt (https://github.com/SUSE/ceph-salt)

    Assumes a Salt cluster is already running (use the Salt task to achieve
    this).

    This task understands the following config keys which apply to
    this task and all its subtasks:

        log_anchor      a string (default: "WWWW: ") which will precede
                        log messages emitted at key points during the
                        deployment
        quiet_salt:
            true        suppress stderr on salt commands (the default)
            false       let salt commands spam the log
        allow_reboots:
            true        Allow cluster nodes to be rebooted if needed (default)
            false       
        deploy:
            true        Enable role deployment on ceph-salt (default)
            false       
    """
    err_prefix = "(ceph_salt task) "

    log_anchor_str = "WWWW: "

    def __init__(self, ctx, config):
        super(CephSalt, self).__init__(ctx, config)
        log.debug("beginning of constructor method")
        if not ceph_salt_ctx:
            self._populate_ceph_salt_context()
            self.log_anchor = ceph_salt_ctx['log_anchor']
            introspect_roles(self.ctx, self.log, quiet=False)
            self.ctx['roles'] = self.ctx.config['roles']
            self.log = log
        self.reboots_explicitly_forbidden = not self.config.get("allow_reboots", True)
        self.master_remote = ceph_salt_ctx['master_remote']
        self.quiet_salt = ceph_salt_ctx['quiet_salt']
        self.nodes = self.ctx['nodes']
        self.nodes_storage = self.ctx['nodes_storage']
        self.nodes_storage_only = self.ctx['nodes_storage_only']
        self.remotes = self.ctx['remotes']
        self.roles = self.ctx['roles']
        self.sm = ceph_salt_ctx['salt_manager_instance']
        self.role_types = self.ctx['role_types']
        self.remote_lookup_table = self.ctx['remote_lookup_table']
        self.ceph_salt_deploy = ceph_salt_ctx['deploy']
        self.cluster = self.config.get('cluster', 'ceph')
        self.testdir = misc.get_testdir(self.ctx)
        if 'cephadm_mode' not in self.config:
            self.config['cephadm_mode'] = 'root'
        assert self.config['cephadm_mode'] in ['root', 'cephadm-package']
        if self.config['cephadm_mode'] == 'root':
            self.ctx.cephadm = self.testdir + '/cephadm'
        else:
            self.ctx.cephadm = 'cephadm'
        self.ctx.daemons = DaemonGroup(use_cephadm = self.ctx.cephadm)
        if not hasattr(self.ctx, 'ceph'):
            self.ctx.ceph = {}
        self.ctx.ceph[self.cluster] = argparse.Namespace()
        self.scripts = Scripts(self.ctx, self.log)
        self.bootstrap_remote = None

    def _install_ceph_salt(self):
        '''
        Installs ceph-salt on master either from source if repo and/or branch are 
        provided in the suite yaml or from rpm if not
        '''
        global ceph_salt_ctx
        if ceph_salt_ctx['repo']:
            if not ceph_salt_ctx['branch']:
                self.scripts.run(
                self.master_remote,
                'install_ceph_salt.sh',
                args=ceph_salt_ctx['repo']
                )
            else:
                self.scripts.run(
                self.master_remote,
                'install_ceph_salt.sh',
                args=[ceph_salt_ctx['repo'], ceph_salt_ctx['branch']]
                )
        else:
            self.scripts.run(
            self.master_remote,
            'install_ceph_salt.sh'
            )
        self.ctx.cluster.run(args='sudo systemctl restart salt-minion')
        self.master_remote.sh("sudo systemctl restart salt-master")

    def _populate_ceph_salt_context(self):
        global ceph_salt_ctx
        ceph_salt_ctx['log_anchor'] = self.config.get('log_anchor', self.log_anchor_str)
        if not isinstance(ceph_salt_ctx['log_anchor'], str):
            self.log.warning(
                "log_anchor was set to non-string value ->{}<-, "
                "changing to empty string"
                .format(ceph_salt_ctx['log_anchor'])
                )
            ceph_salt_ctx['log_anchor'] = ''
        ceph_salt_ctx['deploy'] = self.config.get('deploy', True)
        ceph_salt_ctx['quiet_salt'] = self.config.get('quiet_salt', True)
        ceph_salt_ctx['salt_manager_instance'] = SaltManager(self.ctx)
        ceph_salt_ctx['master_remote'] = (
                ceph_salt_ctx['salt_manager_instance'].master_remote
                )
        ceph_salt_ctx['repo'] = self.config.get('repo', None)
        ceph_salt_ctx['branch'] = self.config.get('branch', None)

    def _add_CA_repo(self):
        '''
        Adding `SUSE Internal CA Certificate` that's needed to install the container image
        '''
        repo_url = 'http://download.suse.de/ibs/SUSE:/CA/SLE_15_SP2/'
        repo_name = 'SUSE Internal CA Certificate'
        self.ctx.cluster.run(args="sudo zypper -n addrepo --refresh --no-gpgcheck {url} '{name}'\n"
                                    "sudo zypper -n in ca-certificates-suse"
                                    .format(url=repo_url, name=repo_name))

    def _rm_localhost_from_etc_hosts(self):
        #FIXME: This is temporary workaround for https://github.com/ceph/ceph-salt/issues/64
        '''
        Teuthology by default puts in '/etc/hosts' a line with the hostnames and localhost ip. This
        causes salt to populate 'fqdn_ip4' with 127.0.0.1 and ceph-salt is breaking since it
        has a exception for localhost resolution. So this function Removes localhost entries from
        '/etc/hosts' in all hosts in order to use DNS server for names resolution.
        '''
        self.log.info(anchored("Removing localhost resolution from /etc/hosts"))
        self.ctx.cluster.run(args= 'sudo sed -i \"/$(hostname)/d\" /etc/hosts' )
        self.log.info("Removed localhost DNS resolution")
        self.ctx.cluster.run(args= 'cat /etc/hosts' )
        self.ctx.cluster.run(args= 'sudo chattr +i /etc/hosts' )

    def _get_bootstrap_remote(self):
        '''
        Get the bootstrap node that's one with 'mon' and 'mgr' roles and will be used by ceph-salt
        for bootstraping the cluster and then by cephadm to deploy the rest of the nodes
        '''
        for host, roles in self.remote_lookup_table.items():
            # possibly use teuthology.is_type() here
            if ("mon" in [r.split('.')[0] for r in roles] and
                "mgr" in [r.split('.')[0] for r in roles]):
                self.bootstrap_remote = self.remotes[host]
                break
        if not self.bootstrap_remote:
            raise ConfigError("No possible bootstrap minion found. Please check the provided roles")
        self.log.info("Bootstrap minion is: {}".format(self.bootstrap_remote.hostname))
        cluster_name = self.cluster
        fsid = str(uuid.uuid1())
        self.log.info('Cluster fsid is %s' % fsid)
        self.ctx.ceph[cluster_name].fsid = fsid
        fsid = self.ctx.ceph[cluster_name].fsid
        self.ctx.ceph[cluster_name].bootstrap_remote = self.bootstrap_remote
        for roles in self.remote_lookup_table[self.bootstrap_remote.hostname]:
            _, role, role_id = misc.split_role(roles)
            if role == 'mon':
                self.ctx.ceph[cluster_name].first_mon = role_id
                break
        for roles in self.remote_lookup_table[self.bootstrap_remote.hostname]:
            _, role, role_id = misc.split_role(roles)
            if role == 'mgr':
                self.ctx.ceph[cluster_name].first_mgr = role_id
                break
        self.log.info('First mon is mon.%s on %s' % (self.ctx.ceph[cluster_name].first_mon,
                                                self.bootstrap_remote.shortname))
        self.log.info('First mgr is mgr.%s on %s' % (self.ctx.ceph[cluster_name].first_mgr,
                                                self.bootstrap_remote.shortname))
        # register initial daemons
        self.ctx.daemons.register_daemon(
        self.bootstrap_remote, 'mon', self.ctx.ceph[cluster_name].first_mon,
        cluster=cluster_name,
        fsid=fsid,
        logger=log.getChild('mon.' + self.ctx.ceph[cluster_name].first_mon),
        wait=False,
        started=True,
        )
        self.ctx.daemons.register_daemon(
        self.bootstrap_remote, 'mgr', self.ctx.ceph[cluster_name].first_mgr,
        cluster=cluster_name,
        fsid=fsid,
        logger=log.getChild('mgr.' + self.ctx.ceph[cluster_name].first_mgr),
        wait=False,
        started=True,
        )

    def _ceph_salt_bootstrap(self):
        '''
        This function populates ceph-salt config according to the configuration on the yaml files
        on the suite regarding node roles, chrony server, dashboard credentials etc and then runs
        the cluster deployment
        '''
        ceph_salt_roles = {"mon": "Mon", "mgr": "Mgr"}
        for host, roles in self.remote_lookup_table.items():
            self.master_remote.sh("sudo ceph-salt config /ceph_cluster/minions add {}".format(host))
        self.master_remote.sh("sudo ceph-salt config /ceph_cluster/roles/admin add \*")
        self.master_remote.sh("sudo ceph-salt config /ceph_cluster/roles/bootstrap set {}"
                              .format(self.bootstrap_remote.hostname))
        self.master_remote.sh("sudo ceph-salt config /system_update/packages disable")
        self.master_remote.sh("sudo ceph-salt config /system_update/reboot disable")
        self.master_remote.sh("sudo ceph-salt config /ssh/ generate")
        self.master_remote.sh("sudo ceph-salt config /containers/images/ceph set"
                              #" docker.io/ceph/daemon-base:latest-master-devel")
                              " registry.suse.de/devel/storage/7.0/cr/containers/ses/7/ceph/ceph")
        self.master_remote.sh("sudo ceph-salt config /time_server/server_hostname set {}"
                              .format(self.master_remote.hostname))
        self.master_remote.sh("sudo ceph-salt config /time_server/external_servers add"
                              " 0.pt.pool.ntp.org")
        self.master_remote.sh("sudo ceph-salt config /cephadm_bootstrap/advanced set mon-id {}"
                              .format(self.ctx.ceph[self.cluster].first_mon))
        self.master_remote.sh("sudo ceph-salt config /cephadm_bootstrap/advanced set mgr-id {}"
                              .format(self.ctx.ceph[self.cluster].first_mgr))
        self.master_remote.sh("sudo ceph-salt config /cephadm_bootstrap/advanced set fsid {}"
                              .format(self.ctx.ceph[self.cluster].fsid))
        self.master_remote.sh("sudo ceph-salt config /cephadm_bootstrap/dashboard/username set admin")
        self.master_remote.sh("sudo ceph-salt config /cephadm_bootstrap/dashboard/password set admin")
        self.master_remote.sh("sudo ceph-salt config ls")
        if self.ceph_salt_deploy:
            self.master_remote.sh("sudo stdbuf -o0 ceph-salt -ldebug deploy --non-interactive")
            self.ctx.ceph[self.cluster].bootstrapped = True

    def __zypper_ps_with_possible_reboot(self):
        if self.sm.all_minions_zypper_ps_requires_reboot():
            log_spec = "Detected updates requiring reboot"
            self.log.warning(anchored(log_spec))
            if self.reboots_explicitly_forbidden:
                self.log.info("Reboots explicitly forbidden in test configuration: not rebooting")
                self.log.warning("Processes using deleted files may cause instability")
            else:
                self.log.warning(anchored("Rebooting the whole cluster now!"))
                self.reboot_the_cluster_now(log_spec=log_spec)
                assert not self.sm.all_minions_zypper_ps_requires_reboot(), \
                    "No more updates requiring reboot anywhere in the whole cluster"

    def reboot_the_cluster_now(self, log_spec=None):
        global reboot_tries
        if not log_spec:
            log_spec = "all nodes reboot now"
        cmd_str = "salt \\* cmd.run reboot"
        if self.quiet_salt:
            cmd_str += " 2> /dev/null"
        remote_exec(
            self.master_remote,
            cmd_str,
            self.log,
            log_spec,
            rerun=False,
            quiet=True,
            tries=reboot_tries,
            )
        self.sm.ping_minions()

    def begin(self):
        global ceph_salt_ctx
        super(CephSalt, self).begin()
        self._get_bootstrap_remote()
        self._add_CA_repo()
        self._rm_localhost_from_etc_hosts()
        self._install_ceph_salt()
        self.sm.ping_minions()
        self.sm.all_minions_zypper_ref()
        self.sm.all_minions_zypper_up_if_needed()
        self.__zypper_ps_with_possible_reboot()
        self.sm.sync_pillar_data(quiet=self.quiet_salt)
        self._ceph_salt_bootstrap()

    def end(self):
        self.log.debug("beginning of end method")
        super(CephSalt, self).end()
        success = self.ctx.summary.get('success', None)
        if success is None:
            self.log.warning("Problem with ctx summary key? ctx is {}".format(self.ctx))
        if not success:
            self.ctx.cluster.run(args="rpm -qa | sort")
        self.log.debug("end of end method")

    def teardown(self):
        self.log.debug("beginning of teardown method")
        super(CephSalt, self).teardown()
        self.log.debug("end of teardown method")



task = CephSalt
