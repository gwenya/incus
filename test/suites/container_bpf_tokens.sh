make_and_import_bpf_testimage() {
  old_dir="$(pwd)"

  bpftool_dir=/tmp/bpftool # use mktemp
  image_dir=/tmp/bpf-testimage # use mktemp
  image_file=/tmp/bpf-testimage.tar.xz # use mktemp
  mkdir -p "$bpftool_dir" "$image_dir/rootfs/bin"

  git clone --depth=1 --recurse-submodules https://github.com/libbpf/bpftool "$bpftool_dir"
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
  rm -rf "$image_dir" "$image_file" "$bpftool_dir"
}

ensure_import_bpf_testimage() {
  if ! incus image alias list | grep -q "^| testimage-bpf\\s*|.*$"; then
      if [ -e "${INCUS_BPF_TEST_IMAGE:-}" ]; then
          incus image import "${INCUS_BPF_TEST_IMAGE}" --alias testimage-bpf
      else
        make_and_import_bpf_testimage
      fi
  fi
}


test_container_bpf_tokens() {
    ensure_import_bpf_testimage
    ensure_has_localhost_remote "${INCUS_ADDR}"

    incus init testimage-bpf foo


    incus delete -f foo
}
