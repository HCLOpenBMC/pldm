libpldm_headers = ['.', './oem/ibm']

sources = [
  'pldm_cmd_helper.cpp',
  'pldm_base_cmd.cpp',
  'pldm_platform_cmd.cpp',
  'pldm_bios_cmd.cpp',
  'pldm_fru_cmd.cpp',
  'pldmtool.cpp',
  'ncsi_util.cpp',
]

if get_option('oem-ibm').enabled()
sources += [
    'oem/ibm/pldm_oem_ibm.cpp',
  ]
endif

libnl = dependency('libnl-3.0')

executable(
  'pldmtool',
  sources,
  implicit_include_directories: false,
  include_directories: include_directories(libpldm_headers),
  dependencies: [libpldm, libpldmutils, sdbusplus, libnl, dependency('phosphor-logging'), dependency('libnl-genl-3.0')],
  install: true,
  install_dir: get_option('bindir'))

ncsi_sources = [
  'ncsitool.cpp',
  'ncsi_util.cpp',
]


executable(
  'ncsitool',
  ncsi_sources,
  implicit_include_directories: false,
  dependencies: [sdbusplus, libnl, dependency('phosphor-logging'), dependency('libnl-genl-3.0')],
  install: true,
  install_dir: get_option('bindir'))

executable(
  'ncsi_client',
  'ncsi_client.cpp',
  implicit_include_directories: false,
  dependencies: [sdbusplus, libnl, dependency('phosphor-logging'), dependency('libnl-genl-3.0')],
  install: true,
  install_dir: get_option('bindir'))

