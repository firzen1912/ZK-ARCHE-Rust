1..50 | ForEach-Object {
  $i = $_.ToString("00")
  $dir = "clients\c$i"
  New-Item -ItemType Directory -Force $dir | Out-Null
  cargo run --release --bin client_test1 -- --server 127.0.0.1:4000 --state-dir $dir --setup
}
