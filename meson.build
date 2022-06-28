project(
    'spdm_responder',
    'cpp',
    license: 'Apache-2.0',
    version: '0.1',
    default_options: [
        'warning_level=3',
        'werror=false',
        'cpp_std=c++17'
    ],
)

spdmapplib = dependency('spdmapplib')

src_files = ['src/spdmd.cpp']

deps = [
    spdmapplib,
]

bindir = get_option('prefix') + '/' +get_option('bindir')
executable('spdm_responder',src_files,
            dependencies: deps,
            install: true,
            install_dir:bindir)
# Install the files into the build directory

systemd = dependency ('systemd')
systemd_system_unit_dir = systemd.get_pkgconfig_variable('systemdsystemunitdir',
                                                         define_variable: ['prefix',
                                                                           get_option('prefix')
                                                                          ])
configure_file(input : 'src/xyz.openbmc_project.spdmd.service',
               output : 'xyz.openbmc_project.spdmd.service',
               copy : true,
               install_dir : systemd_system_unit_dir)
