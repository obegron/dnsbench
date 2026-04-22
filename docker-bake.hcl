group "default" {
  targets = ["linux"]
}

target "linux" {
  context = "."
  dockerfile = "Dockerfile"
  target = "linux-build"
  tags = ["dnsbench:linux-build"]
  output = ["type=docker"]
}
