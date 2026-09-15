package main

import _ "embed"

// La charge est embarquee dans l'installeur, pas telechargee.
//
// Cela le fait peser une trentaine de megaoctets, et c'est le prix d'une
// propriete qui compte pour un outil de securite: il installe et repare sans
// reseau. On ne va pas chercher des binaires sur Internet pendant qu'on repare
// une machine dont on doute justement de l'etat.
//
// Les deux fichiers sont deposes par le script de construction. Leur absence
// fait echouer la compilation, ce qui est voulu: un installeur qui se compile
// sans rien a installer serait un piege.

//go:embed payload/argus.exe
var chargeArgus []byte

//go:embed payload/argus-console.exe
var chargeConsole []byte
