'''
Task that deploys a CAASP cluster on all the nodes
Linter:
    flake8 --max-line-length=100
'''
import logging
import os
from util import remote_exec
from teuthology.exceptions import ConfigError
from teuthology.misc import (
    delete_file,
    move_file,
    sh,
    sudo_write_file,
    write_file,
    copy_file,
    all_roles_of_type
    )
from teuthology.orchestra import run
from teuthology.task import Task
from util import (
    get_remote_for_role,
    remote_exec
    )
log = logging.getLogger(__name__)


class Caasp(Task):
    """
    Deploy a Caasp cluster on all remotes 
    """

    def __init__(self, ctx, config):
        super(Caasp, self).__init__(ctx, config)
        log.debug("beginning of constructor method")
        self.ctx['roles'] = self.ctx.config['roles']
        self.log = log
        self.remotes = self.cluster.remotes
        self.mgmt_remote = get_remote_for_role(self.ctx, "skuba_mgmt_host.0")

    def __install_skuba_to_mgmt(self):
        self.log.info('Installing Skuba on mgmt host')
        self.mgmt_remote.sh("sudo zypper --non-interactive --no-gpg-checks install "
                            "--force --no-recommends skuba kubernetes-client")

    def __copy_key_to_mgmt(self):
        '''
        Copy key from teuthology server to the mgmt one
        '''
        os.system('scp {} {}:{}'.format('/home/ubuntu/.ssh/id_rsa', self.mgmt_remote,
                                        '/home/ubuntu/.ssh/id_rsa'))

    def __check_skuba(self):
        self.log.info('Checking Skuba version')
        self.mgmt_remote.sh("sudo rpm -qa | grep -i skuba")

    def __enable_ssh_agent(self):
        self.log.info('Enabling ssh-agent and adding ssh key to the host')
        self.mgmt_remote.sh("echo '[ -z \"$SSH_AUTH_SOCK\" ] && eval \"$(ssh-agent -s)\" "
                            "&& ssh-add ~/.ssh/id_rsa' >> ~/.bashrc")

    def __create_cluster(self):
        master_remote = get_remote_for_role(self.ctx, "caasp_master.0")
        ssh_agent_prefix = "eval `ssh-agent`; ssh-add ~/.ssh/id_rsa;"
        self.mgmt_remote.sh("skuba cluster init --control-plane {} cluster"
                            .format(master_remote.hostname))
        self.mgmt_remote.sh("export KUBECONFIG=/home/ubuntu/testcluster/admin.conf")
        self.mgmt_remote.sh("cd cluster;skuba node bootstrap --user ubuntu "
                            "--sudo --target {} my-master".format(master_remote.hostname))
        for i in range(sum(1 for x in all_roles_of_type(self.ctx.cluster, 'caasp_worker'))):
            worker_remote = get_remote_for_role(self.ctx, "caasp_worker."+ str(i))
            self.mgmt_remote.sh("cd cluster;skuba node join --role worker "
                                "--user ubuntu --sudo --target {} worker.{}"
                                .format(worker_remote.hostname, str(i)))

    def begin(self):
        self.__check_skuba()
        self.__copy_key_to_mgmt()
        self.__enable_ssh_agent()
        self.__create_cluster()


    def end(self):
        pass

    def teardown(self):
        pass



task = Caasp
