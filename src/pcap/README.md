# PCAP




## Generating the gRPC stubs

Set up the `protoc` compiler with output to gRPC:
https://grpc.io/docs/languages/go/quickstart/

```shell
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
```

## Running on MacOS (including Tests)

You might end up with errors complaining about not having access to capture from local network interfaces.

Change the group for the BPF devices to `staff`:

```shell
sudo chgrp staff /dev/bpf*; sudo chmod g+rw /dev/bpf*; ls -la /dev/bpf*
```

Alternatively:

[Wireshark guide on installing and running on MacOS](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallOSXInstall.html).

Install `ChmodBPF`, available as part of Wireshark.

The path to the installer can be found in Wireshark > About Wireshark > Folders, MacOS Extras.

The installer is called `Install ChmodBPF.pkg`.
