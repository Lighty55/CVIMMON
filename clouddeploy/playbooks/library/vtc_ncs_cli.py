#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import b


def main():

    module = AnsibleModule(
        argument_spec=dict(
            commands=dict(type='list'),
            command=dict(type='str', default=''),
            check_output=dict(type='bool', default=True),
            expected_output=dict(),
            ncs_cli=dict(default='/opt/nso/current/bin/ncs_cli')
        )
    )

    commands = module.params['commands']
    command = module.params['command'].strip()
    ncs_cli = module.params['ncs_cli']
    check_output = module.params['check_output']
    expected_output = module.params['expected_output']

    # User input validation
    if not commands and command == '':
        module.fail_json(rc=256, msg="no command given. Set either "
                                     "'commands' or 'command' argument")

    if commands and command != '':
        module.fail_json(rc=256, msg="Both 'commands' or 'command' "
                                     "are given. Only one allowed")

    # Make actual command string
    if commands and not command:
        command = '\n'.join(commands)

    rc, out, err = module.run_command(ncs_cli, data=command,
                                      use_unsafe_shell=True, encoding=None)

    stdout = out.rstrip(b("\r\n"))
    stderr = err.rstrip(b("\r\n"))

    if 'Commit complete.' in stdout:
        module.exit_json(
            stdout=stdout,
            rc=rc,
            changed=True
        )
    elif 'No modifications to commit.' in stdout:
        module.exit_json(
            stdout=stdout,
            rc=rc,
            changed=False
        )
    elif 'syntax error:' in stdout:
        module.fail_json(msg=stdout)
    elif stdout.startswith('Aborted:'):
        module.fail_json(msg=stdout)

    # If user expects unique stdout
    if check_output and expected_output:
        module.exit_json(
            cmd=command,
            stdout=stdout,
            stderr=stderr,
            rc=rc,
            failed=expected_output not in stdout
        )

    # Fail by default (check_output=True) if output is not recognized
    module.exit_json(
        cmd      = command,
        stdout   = stdout,
        stderr   = stderr,
        rc       = rc,
        failed   = check_output
    )

if __name__ == '__main__':
    main()
