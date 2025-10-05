get_static_bpf_tool() {
  if [ -e "${INCUS_BPFTOOL_STATIC_BINARY:-}" ]; then
    echo "$INCUS_BPFTOOL_STATIC_BINARY"
  else
    old_dir="$(pwd)"

    bpftool_dir=$(mktemp -d -p "${TEST_DIR}" bpftool-XXX)

    mkdir -p "$bpftool_dir"

    git clone --depth=1 --revision=53c1852920c8a8f8ccedb7a64e3d9852949792c7 --recurse-submodules https://github.com/libbpf/bpftool "$bpftool_dir"
    cd "$bpftool_dir/src" || return 1

    EXTRA_LDFLAGS=-static make

    realpath bpftool

    cd "$old_dir" || return 1
  fi
}

unset_bpffs_config() {
  incus config unset foo security.bpffs.path || true
  incus config unset foo security.bpffs.delegate_cmds || true
  incus config unset foo security.bpffs.delegate_maps || true
  incus config unset foo security.bpffs.delegate_progs || true
  incus config unset foo security.bpffs.delegate_attachs || true
}

test_container_bpf_token() {
  ensure_import_testimage

  bpftool_path=$(get_static_bpf_tool)
  file "$bpftool_path"
  incus launch testimage foo
  incus file push "$bpftool_path" foo/bin/bpftool
  incus exec foo -- chmod +x /bin/bpftool
  incus stop foo

  test_container_bpf_token_delegate

  unset_bpffs_config

  test_container_bpf_token_path

  incus delete -f foo
}


test_container_bpf_token_delegate() {
  incus config set foo security.bpffs.delegate_cmds=map_create,prog_attach
  incus config set foo security.bpffs.delegate_maps=hash,array
  incus config set foo security.bpffs.delegate_progs=socket_filter,xdp,kprobe
  incus config set foo security.bpffs.delegate_attachs=cgroup_inet_ingress,sk_skb_stream_parser

  incus start foo
  bpftool_output="$(incus exec foo -- /bin/bpftool --json token list  | jq --sort-keys)"
  incus stop foo

  bpftool_desired_output='
  [
    {
      "token_info": "/sys/fs/bpf",
      "allowed_cmds": [
        "map_create",
        "prog_attach"
      ],
      "allowed_maps": [
        "hash",
        "array"
      ],
      "allowed_progs": [
        "socket_filter",
        "kprobe",
        "xdp"
      ],
      "allowed_attachs": [
        "cgroup_inet_ingress",
        "sk_skb_stream_parser"
      ]
    }
  ]
      '
  bpftool_desired_output=$(echo "$bpftool_desired_output" | jq --sort-keys)

  test "$bpftool_output" = "$bpftool_desired_output"
}

test_container_bpf_token_path() {
  set -e
  incus config set foo security.bpffs.path=/mnt
  # we need to enable one of the delegate settings to enable the token
  set -e
  incus config set foo security.bpffs.delegate_cmds=map_create
  set -e
  incus start foo
  set -e
  bpftool_output="$(incus exec foo -- bpftool --json token list  | jq --sort-keys)"
  set -e
  incus stop foo

  bpftool_desired_output='
  [
    {
      "token_info": "/mnt",
      "allowed_cmds": [
        "map_create"
      ],
      "allowed_maps": [],
      "allowed_progs": [],
      "allowed_attachs": []
    }
  ]
      '
  bpftool_desired_output=$(echo "$bpftool_desired_output" | jq --sort-keys)

  test "$bpftool_output" = "$bpftool_desired_output"
}
