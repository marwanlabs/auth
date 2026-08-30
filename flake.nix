{
  description = "Development environment for authserver";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });
    in {
      devShells = forEachSystem ({ pkgs }: {
        default = pkgs.mkShell {
          packages = [
            # Use nixpkgs' supported default Go toolchain. It is compatible
            # with this module's go 1.22.2 directive.
            pkgs.go
            pkgs.gopls
            pkgs.gotools
            pkgs.caddy
            pkgs.nodejs
            pkgs.typescript
          ];

          shellHook = ''
            export CGO_ENABLED=0
            echo "authserver development environment"
            echo "Go: $(go version)"
          '';
        };
      });
    };
}
