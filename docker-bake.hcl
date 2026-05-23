group "default" {
  targets = ["linux"]
}

group "cross" {
  targets = ["windows"]
}

target "linux" {
  context = "."
  dockerfile = "Dockerfile"
  target = "linux-build"
  tags = ["dnsbench:linux-build"]
  output = ["type=docker"]
}

target "windows" {
  context = "."
  dockerfile = "Dockerfile"
  target = "windows-artifacts"
  output = ["type=local,dest=dist/windows"]
}

target "windows-image" {
  context = "."
  dockerfile = "Dockerfile"
  target = "windows-build"
  tags = ["dnsbench:windows-build"]
  output = ["type=docker"]
}
