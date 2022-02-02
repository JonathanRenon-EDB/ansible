# Abhijit Menon-Sen <ams@2ndQuadrant.com>
# Loosely based on lib/ansible/cli/vault.py
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import io
import os
import sys
import subprocess

from ansible import constants as C
from ansible import context
from ansible.cli import CLI
from ansible.cli.arguments import option_helpers as opt_help
from ansible.errors import AnsibleError, AnsibleOptionsError
from ansible.module_utils._text import to_text, to_bytes
from ansible.parsing.dataloader import DataLoader
from ansible.parsing.vault import VaultLib, match_encrypt_secret
from ansible.utils.display import Display

display = Display()

class VaultpwCLI(CLI):
    '''
    '''

    def __init__(self, args):

        self.encrypt_secret = None
        self.encrypt_vault_id = None
        super(VaultpwCLI, self).__init__(args)

    def init_parser(self):
        super(VaultpwCLI, self).init_parser(
            desc="utility to store or fetch vault-encrypted passwords in YAML inventory files",
            epilog="\nSee '%s <command> --help' for more information on a specific command.\n\n" % os.path.basename(sys.argv[0])
        )
        common = opt_help.argparse.ArgumentParser(add_help=False)
        opt_help.add_vault_options(common)

        subparsers = self.parser.add_subparsers(dest="action")
        subparsers.required = True

        show_parser = subparsers.add_parser(
            "show", help="Show a password", parents=[common]
        )
        show_parser.set_defaults(func=self.execute_show)
        show_parser.add_argument(
            "args", help="Filename", metavar="file_name", nargs="*"
        )
        store_parser = subparsers.add_parser(
            "store", help="store a password", parents=[common]
        )
        store_parser.set_defaults(func=self.execute_store)

        store_parser.add_argument(
            "args", help="Filename", metavar="file_name", nargs="*"
        )
        store_parser.add_argument(
            "-c",
            "--command",
            dest="password_command",
            action="store",
            help="command to run to obtain a password",
        )

    def post_process_args(self, options):
        options = super(VaultpwCLI, self).post_process_args(options)
        self.validate_conflicts(options)

        display.verbosity = options.verbosity

        if options.vault_ids:
            for vault_id in options.vault_ids:
                if u';' in vault_id:
                    raise AnsibleOptionsError("Invalid character ';' found in vault id: %s" % vault_id)

        return options

    def run(self):
        super().run()
        self.loader = DataLoader()

        vault_ids = C.DEFAULT_VAULT_IDENTITY_LIST + list(context.CLIARGS['vault_ids'])

        action = context.CLIARGS["action"]
        if action in ["show", "store"]:
            vault_secrets = self.setup_vault_secrets(
                self.loader,
                vault_ids=vault_ids,
                vault_password_files=list(context.CLIARGS["vault_password_files"]),
                ask_vault_pass=context.CLIARGS["ask_vault_pass"],
            )

            if not vault_secrets:
                raise AnsibleOptionsError(
                    "A vault password is required to use ansible-vault"
                )

            encrypt_vault_id = (
                context.CLIARGS.get("encrypt_vault_id")
                or C.DEFAULT_VAULT_ENCRYPT_IDENTITY
            )
            if len(vault_secrets) > 1 and not encrypt_vault_id:
                raise AnsibleOptionsError(
                    "Use '--encrypt-vault-id id' to choose one of the following vault ids to use for encryption: %s"
                    % ",".join([x[0] for x in vault_secrets])
                )

            encrypt_secret = match_encrypt_secret(
                vault_secrets, encrypt_vault_id=encrypt_vault_id
            )

            self.encrypt_vault_id = encrypt_secret[0]
            self.encrypt_secret = encrypt_secret[1]

            self.loader.set_vault_secrets(vault_secrets)

            self.vault = VaultLib(vault_secrets)

        if len(context.CLIARGS["args"]) != 1:
            raise AnsibleOptionsError("Exactly one inventory file must be specified")

        self.file = os.path.expanduser(context.CLIARGS['args'][0])

        old_umask = os.umask(0o077)

        context.CLIARGS["func"]()

        os.umask(old_umask)

    def execute_store(self):
        '''
        Takes the path to an inventory file such as
        inventory/group_vars/tag_Cluster_xxx/secrets/example_password.yml and
        overwrites the file with an assignment of "example_password: password"
        in vault-encrypted YAML format. The password is obtained by prompting
        the user or, if a command is specified, by running the command and
        reading stdout.
        '''

        b_plaintext = b''

        command = context.CLIARGS['password_command']
        if command:
            try:
                pw = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if pw.returncode != 0:
                    raise Exception('non-zero exit code: %s' % pw.returncode)
                b_plaintext = pw.stdout.strip()
            except Exception as e:
                print("ERROR: password command failed: %s" % str(e), file=sys.stderr)
                sys.exit(-1)
        else:
            b_plaintext = to_bytes(display.prompt("Password: ", private=True))

        try:
            b_ciphertext = self.vault.encrypt(
                b_plaintext, secret=self.encrypt_secret,
                vault_id=self.encrypt_vault_id
            )
        except Exception as e:
            print("ERROR: cannot encrypt password: %s" % str(e), file=sys.stderr)
            sys.exit(-1)

        name = os.path.basename(self.file).replace('.yml', '')

        lines = []
        lines.append("%s: !vault |\n" % name)
        for l in to_text(b_ciphertext).splitlines():
            lines.append("    %s\n" % l)

        try:
            fh = open(self.file, 'wb')
            fh.write(to_bytes(''.join(lines)))
            fh.close()
        except Exception as e:
            print("ERROR: cannot write output to %s: %s" % (self.file, str(e)), file=sys.stderr)
            sys.exit(-1)

    def execute_show(self):
        '''
        Takes the path to an inventory file such as
        inventory/group_vars/tag_Cluster_xxx/secrets/example_password.yml and
        prints the password defined therein. The file must contain a variable
        assignment of the form "example_password: password"; either the whole
        file is vault-encrypted, or only the password is.
        '''

        if not os.path.exists(self.file):
            print("ERROR: inventory file does not exist: %s" % self.file, file=sys.stderr)
            sys.exit(-1)

        try:
            name = os.path.basename(self.file).replace('.yml', '')
            y = self.loader.load_from_file(self.file)
            print(y[name])
        except Exception as e:
            print("ERROR: cannot show password from %s: %s" % (self.file, str(e)), file=sys.stderr)
            sys.exit(-1)
