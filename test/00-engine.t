#!/usr/bin/perl
  <<<<<<< magma_impl
use Test::More tests => 7;
  =======
  <<<<<<< openssl_1_1_0_release1
use Test::More tests => 7;
  =======
use Test2::V0;
plan(7);
  >>>>>>> master
  >>>>>>> master
use Cwd 'abs_path';

# prepare data for 

  <<<<<<< magma_impl
  =======
  <<<<<<< openssl_1_1_0_release1
  >>>>>>> master
open F,">","testdata.dat";
print F "12345670" x 128;
close F;

# Set OPENSSL_ENGINES environment variable to just built engine
if(!defined $ENV{'OPENSSL_ENGINES'}){
  <<<<<<< magma_impl
	$ENV{'OPENSSL_ENGINES'} = abs_path("../.libs");
}

$key='0123456789abcdef' x 2;
  =======
	$ENV{'OPENSSL_ENGINES'} = abs_path("../bin");
}

$key='0123456789abcdef' x 2;
  =======
open (my $F,">","testdata.dat");
print $F "12345670" x 128;
close $F;

my $key='0123456789abcdef' x 2;
  >>>>>>> master
  >>>>>>> master

#
# You can redefine engine to use using ENGINE_NAME environment variable
# 
  <<<<<<< magma_impl
$engine=$ENV{'ENGINE_NAME'}||"gost";
  =======
  <<<<<<< openssl_1_1_0_release1
$engine=$ENV{'ENGINE_NAME'}||"gost";
  =======
my $engine=$ENV{'ENGINE_NAME'}||"gost";
  >>>>>>> master
  >>>>>>> master

# Reopen STDERR to eliminate extra output
open STDERR, ">>","tests.err";

if (exists $ENV{'OPENSSL_CONF'}) {
	delete $ENV{'OPENSSL_CONF'}
}
#
# This test needs output of openssl engine -c command.
# Default one  is hardcoded below, but you can place file
# ${ENGINE_NAME}.info into this directory if you use this test suite
# to test other engine implementing GOST cryptography.
#
  <<<<<<< magma_impl
  =======
  <<<<<<< openssl_1_1_0_release1
  =======
my $engine_info;

  >>>>>>> master
  >>>>>>> master
if ( -f $engine . ".info") {
	diag("Reading $engine.info");
	open F, "<", $engine . ".info";
	read F,$engine_info,1024;
} else {

$engine_info= <<EOINF;
(gost) Reference implementation of GOST engine
  <<<<<<< magma_impl
 [gost89, gost89-cnt, gost89-cnt-12, gost89-cbc, grasshopper-ecb, grasshopper-cbc, grasshopper-cfb, grasshopper-ofb, grasshopper-ctr, magma-cbc, magma-ctr, id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm, md_gost94, gost-mac, md_gost12_256, md_gost12_512, gost-mac-12, magma-mac, grasshopper-mac, gost2001, gost-mac, gost2012_256, gost2012_512, gost-mac-12, magma-mac, grasshopper-mac]
  =======
  <<<<<<< openssl_1_1_0_release1
 [gost89, gost89-cnt, gost89-cnt-12, gost89-cbc, grasshopper-ecb, grasshopper-cbc, grasshopper-cfb, grasshopper-ofb, grasshopper-ctr, md_gost94, gost-mac, md_gost12_256, md_gost12_512, gost-mac-12, gost2001, gost-mac, gost2012_256, gost2012_512, gost-mac-12]
  =======
 [gost89, gost89-cnt, gost89-cnt-12, gost89-cbc, kuznyechik-ecb, kuznyechik-cbc, kuznyechik-cfb, kuznyechik-ofb, kuznyechik-ctr, magma-cbc, magma-ctr, magma-ctr-acpkm, magma-ctr-acpkm-omac, kuznyechik-ctr-acpkm, kuznyechik-ctr-acpkm-omac, magma-kexp15, kuznyechik-kexp15, md_gost94, gost-mac, md_gost12_256, md_gost12_512, gost-mac-12, magma-mac, kuznyechik-mac, kuznyechik-ctr-acpkm-omac, gost2001, id-GostR3410-2001DH, gost-mac, gost2012_256, gost2012_512, gost-mac-12, magma-mac, kuznyechik-mac, magma-ctr-acpkm-omac, kuznyechik-ctr-acpkm-omac]
  >>>>>>> master
  >>>>>>> master
EOINF
}

$ENV{'OPENSSL_CONF'}=abs_path("no_such_file.cfg");
is(`openssl engine -c $engine`,
$engine_info,
"load engine without any config");

is(`openssl dgst -engine $engine -md_gost94 testdata.dat`,
"md_gost94(testdata.dat)= f7fc6d16a6a5c12ac4f7d320e0fd0d8354908699125e09727a4ef929122b1cae\n",
"compute digest without config");


  <<<<<<< magma_impl
open F,">","test.cnf";
print F <<EOCFG;
  =======
  <<<<<<< openssl_1_1_0_release1
open F,">","test.cnf";
print F <<EOCFG;
  =======
open $F,">","test.cnf";
print $F <<EOCFG;
  >>>>>>> master
  >>>>>>> master
openssl_conf = openssl_def
[openssl_def]
engines = engines
[engines]
${engine}=gost_conf
[gost_conf]
default_algorithms = ALL

EOCFG
  <<<<<<< magma_impl
close F;
  =======
  <<<<<<< openssl_1_1_0_release1
close F;
  =======
close $F;
  >>>>>>> master
  >>>>>>> master
$ENV{'OPENSSL_CONF'}=abs_path('test.cnf');

is(`openssl engine -c $engine`,
$engine_info,
"load engine with config");

is(`openssl dgst -md_gost94 testdata.dat`,
"md_gost94(testdata.dat)= f7fc6d16a6a5c12ac4f7d320e0fd0d8354908699125e09727a4ef929122b1cae\n",
"compute digest with config without explicit engine param");

is(`openssl dgst -engine $engine -md_gost94 testdata.dat`,
"md_gost94(testdata.dat)= f7fc6d16a6a5c12ac4f7d320e0fd0d8354908699125e09727a4ef929122b1cae\n",
"compute digest with both config and explicit engine param");

like(`openssl ciphers`, qr|GOST2001-GOST89-GOST89|, 'display GOST2001-GOST89-GOST89 cipher');

like(`openssl ciphers`, qr|GOST2012-GOST8912-GOST8912|, 'display GOST2012-GOST8912-GOST8912 cipher');

unlink('testdata.dat');
unlink('test.cnf');
