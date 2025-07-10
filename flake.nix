{
  description = "Flake Configuration";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1.*.tar.gz";
  };
  outputs =
    { self
    , nixpkgs
    ,
    }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-darwin" ];
      forEachSupportedSystem = f:
        nixpkgs.lib.genAttrs supportedSystems (system:
          f {
            pkgs = import nixpkgs {
              inherit system;
            };
          });
    in
    {
      devShells = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            libbpf
            jdk23
            maven
            bpftools
            llvmPackages_20.clang-unwrapped
          ];
          shellHook = ''
            echo ${pkgs.libbpf}/lib
            export LD_LIBRARY_PATH=${pkgs.libbpf}/lib:$LD_LIBRARY_PATH
          '';
        };
      });
    };
}