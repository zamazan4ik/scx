# BPF compilation uses the gen_bpf_o generator. The following should be
# passed in as extra_args.
bpf_includes = ['-I', join_paths(meson.current_source_dir(), 'include'),
                '-I', join_paths(meson.current_source_dir(), 'include/arch/' + arch_dict[cpu]),
                '-I', join_paths(meson.current_source_dir(), 'include/bpf-compat'),]

# Common include paths for user C compilation. The following should be
# passed in as executable::include_directories.
user_c_includes = include_directories('include')

install_subdir(join_paths(meson.current_source_dir(), 'include/scx'), install_dir: 'include', install_tag: 'devel')

subdir('c')
