root_ssh = '#!/bin/ash\n'\
       'dropbear_config=/etc/default/dropbear\n'\
       'disable_root=\"DROPBEAR_EXTRA_ARGS=\\\"-w\\\"\"\n'\
       'root_pw=\'<PASSWORD>\'\n'\
       '\n'\
       '# Enable root ssh\n'\
       'enable(){\n'\
       '    echo /dev/null > $dropbear_config\n'\
       '    echo \'root:\' | chpasswd\n'\
       '    echo \"enable!\"\n'\
       '}\n'\
       '\n'\
       '# Disable root ssh\n'\
       'disable(){\n'\
       '    echo $disable_root > $dropbear_config\n'\
       '    echo \"root:$root_pw\" | chpasswd\n'\
       '    echo \"disable!\"\n'\
       '}\n'\
       '\n'\
       'while getopts ed option\n'\
       'do\n'\
       '    case \"${option}\" in\n'\
       '        e) enable;;\n'\
       '        d) disable;;\n'\
       '     esac\n'\
       'done'

test_cmd = '#!/bin/bash\n'\
       'dst_dir=/tmp\n'\
       'disable_root=\"DROPBEAR_EXTRA_ARGS=\\\"-w\\\"\"\n'\
       'root_pw=\'<PASSWORD>\'\n'\
       '\n'\
       'while getopts ed option\n'\
       'do\n'\
       '    case \"${option}\" in\n'\
       '        e) touch $dst_dir/enable\n' \
       '           echo Enabling...\n' \
       '           ;;\n'\
       '        d) touch $dst_dir/disable\n' \
       '           echo Disabling...\n' \
       '           ;;\n'\
       '     esac\n'\
       'done\n' \
       'exit 0\n'
