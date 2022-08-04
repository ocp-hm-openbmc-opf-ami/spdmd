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
libspdm = dependency('libspdm')
libspdm_partial_dep = libspdm.partial_dependency(compile_args : true, link_args: true,
     includes : true, links: false)
systemd = dependency ('systemd')
src_files = ['src/spdmd.cpp',
             'src/util.cpp' ]

deps = [
    spdmapplib,
    libspdm_partial_dep,
    systemd
]


executable('spdm_responder',src_files,
            dependencies: deps,
            install: true,
            install_dir:get_option('bindir'))

systemd_system_unit_dir = systemd.get_pkgconfig_variable('systemdsystemunitdir',
                                                         define_variable: ['prefix',
                                                                           get_option('prefix')
                                                                          ])
# Install the service file into the system unit directory
configure_file(input : 'src/xyz.openbmc_project.spdmd.service',
               output : 'xyz.openbmc_project.spdmd.service',
               copy : true,
               install_dir : systemd_system_unit_dir)
