get_static_bpf_tool() {
  if [ -e "${INCUS_BPFTOOL_STATIC_BINARY:-}" ]; then
    echo "$INCUS_BPFTOOL_STATIC_BINARY"
  else
    archive_path=$(mktemp -p "${TEST_DIR}" bpftool-XXX.tar.xz)
    unpack_path=$(mktemp -d -p "${TEST_DIR}" bpftool-XXX)

    curl -L -o "$archive_path" https://github.com/libbpf/bpftool/releases/download/v7.6.0/bpftool-v7.6.0-amd64.tar.gz

    tar xf "$archive_path" -C "$unpack_path"

    echo "$unpack_path/bpftool"
  fi
}


test_container_bpf_token() {
  ensure_import_testimage

  bpftool_path=$(get_static_bpf_tool)
  file "$bpftool_path"
  set -e
  echo "before launch"
  incus launch testimage foo
  echo "after launch"
  set -e
  incus file push "$bpftool_path" foo/bin/bpftool
  set -e
  incus exec foo -- chmod +x /bin/bpftool
  set -e
  incus stop foo
  set -e
  test_container_bpf_token_delegate
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
      incus config set foo security.bpffs.path=/bpffs

      # we need to enable one of the delegate settings to enable the token
      incus config set foo security.bpffs.delegate_cmds=map_create
      incus config unset foo security.bpffs.delegate_attachs
      incus config unset foo security.bpffs.delegate_maps
      incus config unset foo security.bpffs.delegate_progs

      incus start foo

      bpftool_output="$(incus exec foo -- bpftool --json token list  | jq --sort-keys)"

      incus stop foo

      bpftool_desired_output='
  [
    {
      "token_info": "/bpffs",
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
