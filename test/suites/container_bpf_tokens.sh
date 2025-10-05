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

  bpf_token_test "" "map_create,prog_attach" "hash,array" "socket_filter,xdp,kprobe" "cgroup_inet_ingress,sk_skb_stream_parser"
  bpf_token_test "" "any" "any" "any" "any"
  bpf_token_test "" "map_create" "" "" ""
  bpf_token_test "" "" "hash" "" ""
  bpf_token_test "" "" "" "socket_filter" ""
  bpf_token_test "" "" "" "" "cgroup_inet_ingress"
  bpf_token_test "/mnt" "map_create" "" "" ""

  incus delete -f foo
}

bpf_token_test() {
  path="$1"
  cmds="$2"
  maps="$3"
  progs="$4"
  attachs="$5"

  if [ "$path" != "" ]; then
    incus config set foo security.bpffs.path="$path"
  else
    incus config unset foo security.bpffs.path || true
  fi

  if [ "$cmds" != "" ]; then
    incus config set foo security.bpffs.delegate_cmds="$cmds"
  else
    incus config unset foo security.bpffs.delegate_cmds || true
  fi

  if [ "$maps" != "" ]; then
    incus config set foo security.bpffs.delegate_maps="$maps"
  else
    incus config unset foo security.bpffs.delegate_maps || true
  fi

  if [ "$progs" != "" ]; then
    incus config set foo security.bpffs.delegate_progs="$progs"
  else
    incus config unset foo security.bpffs.delegate_progs || true
  fi

  if [ "$attachs" != "" ]; then
    incus config set foo security.bpffs.delegate_attachs="$attachs"
  else
    incus config unset foo security.bpffs.delegate_attachs || true
  fi

  incus start foo
  bpftool_output="$(incus exec foo -- /bin/bpftool --json token list  | jq --sort-keys)"
  incus stop foo
  expected_path="${path:-/sys/fs/bpf}"
  expected_cmds="$(echo "$cmds" | tr ',' '\n' | sort)"
  expected_maps="$(echo "$maps" | tr ',' '\n' | sort)"
  expected_progs="$(echo "$progs" | tr ',' '\n' | sort)"
  expected_attachs="$(echo "$attachs" | tr ',' '\n' | sort)"

  got_path="$(echo "$bpftool_output" | jq -r '.[0].token_info')"
  got_cmds="$(echo "$bpftool_output" | jq -r '.[0].allowed_cmds.[]' | sort)"
  got_maps="$(echo "$bpftool_output" | jq -r '.[0].allowed_maps.[]' | sort)"
  got_progs="$(echo "$bpftool_output" | jq -r '.[0].allowed_progs.[]' | sort)"
  got_attachs="$(echo "$bpftool_output" | jq -r '.[0].allowed_attachs.[]' | sort)"

  test "$expected_path" = "$got_path"
  test "$expected_cmds" = "$got_cmds"
  test "$expected_maps" = "$got_maps"
  test "$expected_progs" = "$got_progs"
  test "$expected_attachs" = "$got_attachs"
}
