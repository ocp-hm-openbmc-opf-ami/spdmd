project(
    'spdmd',
    'cpp',
    license: 'Apache-2.0',
    version: '0.1',
    default_options: [
        'warning_level=3',
        'werror=false',
        'cpp_std=c++17'
    ],
)
yocto_build = get_option('yocto_dep')
spdmapplib = dependency('spdmapplib')
systemd = dependency ('systemd')

packagedir = join_paths(
    get_option('prefix'),
    get_option('datadir'),
    meson.project_name(),
)

threads = dependency('threads')

cmake = import('cmake')

certificates = [
    'bundle_responder.certchain.der',
    'bundle_responder.certchain1.der',
    'ca.cert.der',
    'end_responder.key'
]
filepaths = []
foreach c : certificates
    file = join_paths('sample_keys/ecp384', c)
    install_data(
        file,
        install_dir: join_paths(
            packagedir,
            'sample_keys/ecp384',
        )
    )
    filepaths += [file]
endforeach
src_files = ['src/spdmd.cpp',
             'src/util.cpp' ]

deps = [
    spdmapplib,
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
configure_file(input : 'service_files/xyz.openbmc_project.spdmd.service',
               output : 'xyz.openbmc_project.spdmd.service',
               copy : true,
               install_dir : systemd_system_unit_dir)
