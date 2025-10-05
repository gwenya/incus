ensure_import_bpf_testimage() {
  if ! incus image alias list | grep -q "^| testimage-bpf\\s*|.*$"; then
      if [ -e "${INCUS_BPF_TEST_IMAGE:-}" ]; then
          incus image import "${INCUS_BPF_TEST_IMAGE}" --alias testimage-bpf
      else
        ensure_import_testimage
        old_dir="$(pwd)"

        bpftool_dir=$(mktemp -d -p "${TEST_DIR}" bpftool-XXX)
        image_dir=$(mktemp -d -p "${TEST_DIR}" bpf-testimage-XXX)
        image_file=$(mktemp -p "${TEST_DIR}" bpf-testimage-XXX.tar.xz)
        testimage_file=$(mktemp -p "${TEST_DIR}" testimage-XXX)

        mkdir -p "$bpftool_dir" "$image_dir"

        incus image export testimage "$testimage_file"
        testimage_file="${testimage_file}.tar.xz"

        tar xf "$testimage_file" -C "$image_dir"

        git clone --depth=1 --branch=v7.6.0 --recurse-submodules https://github.com/libbpf/bpftool "$bpftool_dir"
        cd "$bpftool_dir/src" || return 1

        EXTRA_LDFLAGS=-static make

        cp "bpftool" "$image_dir/rootfs/bin/bpftool"

        arch="$(uname -m)"
        now="$(date +%s)"

        cat > "$image_dir/metadata.yaml" <<EOF
architecture: $arch
creation_date: $now
properties:
  description: Bpftool $arch
EOF

        cd "$image_dir" || return 1
        tar cJf "$image_file" .

        incus image import "$image_file" --alias testimage-bpf

        cd "$old_dir" || return 1
        rm -rf "$bpftool_dir" "$image_dir" "$image_file" "$testimage_file"
      fi
  fi
}


test_container_bpf_token() {
    ensure_import_bpf_testimage

    incus launch testimage-bpf foo \
      security.bpffs.delegate_cmds=map_create,prog_attach \
      security.bpffs.delegate_maps=hash,array \
      security.bpffs.delegate_progs=socket_filter,xdp,kprobe \
      security.bpffs.delegate_attachs=cgroup_inet_ingress,sk_skb_stream_parser

    bpftool_output="$(incus exec foo -- bpftool --json token list  | jq --sort-keys)"
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

    diff <(echo "$bpftool_output") <(echo "$bpftool_desired_output") > /dev/null

    incus delete -f foo
}
