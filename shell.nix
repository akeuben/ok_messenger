{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    # nativeBuildInputs is usually what you want -- tools you need to run
    buildInputs = with pkgs; [ 
        gradle 
        openjdk21
    ];
}

