#!/usr/bin/perl
# ssl-cipher-suite-enum
# Copyright (C) 2012 Mark lowe (mrl@portcullis-security.com)
# 
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then 
# do not use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as 
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# You are encouraged to send comments, improvements or suggestions to
# me at mrl@portcullis-security.com
#
use strict;
use warnings;
use IO::Socket::INET;
use Data::Dumper;

my $VERSION = "0.2-beta";
my $usage = "Starting ssl-cipher-enum v$VERSION ( http://labs.portcullis.co.uk/application/ssl-cipher-suite-enum/ )
Copyright (C) 2012 Mark Lowe (mrl\@portcullis-security.com)

$0 host port
";
my $email = '';
my $host = shift or die $usage;
my $port = shift or die $usage;
my $debug = shift;
$debug = 0 unless defined($debug);

my $ip =  gethostbyname($host);
if (defined($ip)) {
	$ip = inet_ntoa($ip);
} else {
	print "[E] Cannot resolve $host\n";
	exit 1;
}

# flush after every write
$| = 1;

# Most of the TLS cipher suites are listed on http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
my $ciphersuitenamestring = "
0x0000	TLS_NULL_WITH_NULL_NULL	[RFC5246]
0x0001	TLS_RSA_WITH_NULL_MD5	[RFC5246]
0x0002	TLS_RSA_WITH_NULL_SHA	[RFC5246]
0x0003	TLS_RSA_EXPORT_WITH_RC4_40_MD5	[RFC4346][RFC6347]
0x0004	TLS_RSA_WITH_RC4_128_MD5	[RFC5246][RFC6347]
0x0005	TLS_RSA_WITH_RC4_128_SHA	[RFC5246][RFC6347]
0x0006	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5	[RFC4346]
0x0007	TLS_RSA_WITH_IDEA_CBC_SHA	[RFC5469]
0x0008	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA	[RFC4346]
0x0009	TLS_RSA_WITH_DES_CBC_SHA	[RFC5469]
0x000A	TLS_RSA_WITH_3DES_EDE_CBC_SHA	[RFC5246]
0x000B	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA	[RFC4346]
0x000C	TLS_DH_DSS_WITH_DES_CBC_SHA	[RFC5469]
0x000D	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA	[RFC5246]
0x000E	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA	[RFC4346]
0x000F	TLS_DH_RSA_WITH_DES_CBC_SHA	[RFC5469]
0x0010	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA	[RFC5246]
0x0011	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA	[RFC4346]
0x0012	TLS_DHE_DSS_WITH_DES_CBC_SHA	[RFC5469]
0x0013	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA	[RFC5246]
0x0014	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA	[RFC4346]
0x0015	TLS_DHE_RSA_WITH_DES_CBC_SHA	[RFC5469]
0x0016	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA	[RFC5246]
0x0017	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5	[RFC4346][RFC6347]
0x0018	TLS_DH_anon_WITH_RC4_128_MD5	[RFC5246][RFC6347]
0x0019	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA	[RFC4346]
0x001A	TLS_DH_anon_WITH_DES_CBC_SHA	[RFC5469]
0x001B	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA	[RFC5246]
0x001E	TLS_KRB5_WITH_DES_CBC_SHA	[RFC2712]
0x001F	TLS_KRB5_WITH_3DES_EDE_CBC_SHA	[RFC2712]
0x0020	TLS_KRB5_WITH_RC4_128_SHA	[RFC2712][RFC6347]
0x0021	TLS_KRB5_WITH_IDEA_CBC_SHA	[RFC2712]
0x0022	TLS_KRB5_WITH_DES_CBC_MD5	[RFC2712]
0x0023	TLS_KRB5_WITH_3DES_EDE_CBC_MD5	[RFC2712]
0x0024	TLS_KRB5_WITH_RC4_128_MD5	[RFC2712][RFC6347]
0x0025	TLS_KRB5_WITH_IDEA_CBC_MD5	[RFC2712]
0x0026	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA	[RFC2712]
0x0027	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA	[RFC2712]
0x0028	TLS_KRB5_EXPORT_WITH_RC4_40_SHA	[RFC2712][RFC6347]
0x0029	TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5	[RFC2712]
0x002A	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5	[RFC2712]
0x002B	TLS_KRB5_EXPORT_WITH_RC4_40_MD5	[RFC2712][RFC6347]
0x002C	TLS_PSK_WITH_NULL_SHA	[RFC4785]
0x002D	TLS_DHE_PSK_WITH_NULL_SHA	[RFC4785]
0x002E	TLS_RSA_PSK_WITH_NULL_SHA	[RFC4785]
0x002F	TLS_RSA_WITH_AES_128_CBC_SHA	[RFC5246]
0x0030	TLS_DH_DSS_WITH_AES_128_CBC_SHA	[RFC5246]
0x0031	TLS_DH_RSA_WITH_AES_128_CBC_SHA	[RFC5246]
0x0032	TLS_DHE_DSS_WITH_AES_128_CBC_SHA	[RFC5246]
0x0033	TLS_DHE_RSA_WITH_AES_128_CBC_SHA	[RFC5246]
0x0034	TLS_DH_anon_WITH_AES_128_CBC_SHA	[RFC5246]
0x0035	TLS_RSA_WITH_AES_256_CBC_SHA	[RFC5246]
0x0036	TLS_DH_DSS_WITH_AES_256_CBC_SHA	[RFC5246]
0x0037	TLS_DH_RSA_WITH_AES_256_CBC_SHA	[RFC5246]
0x0038	TLS_DHE_DSS_WITH_AES_256_CBC_SHA	[RFC5246]
0x0039	TLS_DHE_RSA_WITH_AES_256_CBC_SHA	[RFC5246]
0x003A	TLS_DH_anon_WITH_AES_256_CBC_SHA	[RFC5246]
0x003B	TLS_RSA_WITH_NULL_SHA256	[RFC5246]
0x003C	TLS_RSA_WITH_AES_128_CBC_SHA256	[RFC5246]
0x003D	TLS_RSA_WITH_AES_256_CBC_SHA256	[RFC5246]
0x003E	TLS_DH_DSS_WITH_AES_128_CBC_SHA256	[RFC5246]
0x003F	TLS_DH_RSA_WITH_AES_128_CBC_SHA256	[RFC5246]
0x0040	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256	[RFC5246]
0x0041	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA	[RFC5932]
0x0042	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA	[RFC5932]
0x0043	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA	[RFC5932]
0x0044	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA	[RFC5932]
0x0045	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA	[RFC5932]
0x0046	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA	[RFC5932]
0x0062  TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA     http://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01
0x0063  TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA http://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01
0x0064  TLS_RSA_EXPORT1024_WITH_RC4_56_SHA      http://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01
0x0065  TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA  http://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01
0x0066  TLS_DHE_DSS_WITH_RC4_128_SHA            http://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01
0x0067	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256	[RFC5246]
0x0068	TLS_DH_DSS_WITH_AES_256_CBC_SHA256	[RFC5246]
0x0069	TLS_DH_RSA_WITH_AES_256_CBC_SHA256	[RFC5246]
0x006A	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256	[RFC5246]
0x006B	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256	[RFC5246]
0x006C	TLS_DH_anon_WITH_AES_128_CBC_SHA256	[RFC5246]
0x006D	TLS_DH_anon_WITH_AES_256_CBC_SHA256	[RFC5246]
0x0080  TLS_GOSTR341094_WITH_28147_CNT_IMIT http://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04
0x0081  TLS_GOSTR341001_WITH_28147_CNT_IMIT http://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04
0x0082  TLS_GOSTR341094_WITH_NULL_GOSTR3411 http://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04
0x0083  TLS_GOSTR341001_WITH_NULL_GOSTR3411 http://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04
0x0084	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA	[RFC5932]
0x0085	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA	[RFC5932]
0x0086	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA	[RFC5932]
0x0087	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA	[RFC5932]
0x0088	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA	[RFC5932]
0x0089	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA	[RFC5932]
0x008A	TLS_PSK_WITH_RC4_128_SHA	[RFC4279][RFC6347]
0x008B	TLS_PSK_WITH_3DES_EDE_CBC_SHA	[RFC4279]
0x008C	TLS_PSK_WITH_AES_128_CBC_SHA	[RFC4279]
0x008D	TLS_PSK_WITH_AES_256_CBC_SHA	[RFC4279]
0x008E	TLS_DHE_PSK_WITH_RC4_128_SHA	[RFC4279][RFC6347]
0x008F	TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA	[RFC4279]
0x0090	TLS_DHE_PSK_WITH_AES_128_CBC_SHA	[RFC4279]
0x0091	TLS_DHE_PSK_WITH_AES_256_CBC_SHA	[RFC4279]
0x0092	TLS_RSA_PSK_WITH_RC4_128_SHA	[RFC4279][RFC6347]
0x0093	TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA	[RFC4279]
0x0094	TLS_RSA_PSK_WITH_AES_128_CBC_SHA	[RFC4279]
0x0095	TLS_RSA_PSK_WITH_AES_256_CBC_SHA	[RFC4279]
0x0096	TLS_RSA_WITH_SEED_CBC_SHA	[RFC4162]
0x0097	TLS_DH_DSS_WITH_SEED_CBC_SHA	[RFC4162]
0x0098	TLS_DH_RSA_WITH_SEED_CBC_SHA	[RFC4162]
0x0099	TLS_DHE_DSS_WITH_SEED_CBC_SHA	[RFC4162]
0x009A	TLS_DHE_RSA_WITH_SEED_CBC_SHA	[RFC4162]
0x009B	TLS_DH_anon_WITH_SEED_CBC_SHA	[RFC4162]
0x009C	TLS_RSA_WITH_AES_128_GCM_SHA256	[RFC5288]
0x009D	TLS_RSA_WITH_AES_256_GCM_SHA384	[RFC5288]
0x009E	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256	[RFC5288]
0x009F	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384	[RFC5288]
0x00A0	TLS_DH_RSA_WITH_AES_128_GCM_SHA256	[RFC5288]
0x00A1	TLS_DH_RSA_WITH_AES_256_GCM_SHA384	[RFC5288]
0x00A2	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256	[RFC5288]
0x00A3	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384	[RFC5288]
0x00A4	TLS_DH_DSS_WITH_AES_128_GCM_SHA256	[RFC5288]
0x00A5	TLS_DH_DSS_WITH_AES_256_GCM_SHA384	[RFC5288]
0x00A6	TLS_DH_anon_WITH_AES_128_GCM_SHA256	[RFC5288]
0x00A7	TLS_DH_anon_WITH_AES_256_GCM_SHA384	[RFC5288]
0x00A8	TLS_PSK_WITH_AES_128_GCM_SHA256	[RFC5487]
0x00A9	TLS_PSK_WITH_AES_256_GCM_SHA384	[RFC5487]
0x00AA	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256	[RFC5487]
0x00AB	TLS_DHE_PSK_WITH_AES_256_GCM_SHA384	[RFC5487]
0x00AC	TLS_RSA_PSK_WITH_AES_128_GCM_SHA256	[RFC5487]
0x00AD	TLS_RSA_PSK_WITH_AES_256_GCM_SHA384	[RFC5487]
0x00AE	TLS_PSK_WITH_AES_128_CBC_SHA256	[RFC5487]
0x00AF	TLS_PSK_WITH_AES_256_CBC_SHA384	[RFC5487]
0x00B0	TLS_PSK_WITH_NULL_SHA256	[RFC5487]
0x00B1	TLS_PSK_WITH_NULL_SHA384	[RFC5487]
0x00B2	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256	[RFC5487]
0x00B3	TLS_DHE_PSK_WITH_AES_256_CBC_SHA384	[RFC5487]
0x00B4	TLS_DHE_PSK_WITH_NULL_SHA256	[RFC5487]
0x00B5	TLS_DHE_PSK_WITH_NULL_SHA384	[RFC5487]
0x00B6	TLS_RSA_PSK_WITH_AES_128_CBC_SHA256	[RFC5487]
0x00B7	TLS_RSA_PSK_WITH_AES_256_CBC_SHA384	[RFC5487]
0x00B8	TLS_RSA_PSK_WITH_NULL_SHA256	[RFC5487]
0x00B9	TLS_RSA_PSK_WITH_NULL_SHA384	[RFC5487]
0x00BA	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256	[RFC5932]
0x00BB	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256	[RFC5932]
0x00BC	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256	[RFC5932]
0x00BD	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256	[RFC5932]
0x00BE	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256	[RFC5932]
0x00BF	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256	[RFC5932]
0x00FF	TLS_EMPTY_RENEGOTIATION_INFO_SCSV	[RFC5746]
0x00C0	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256	[RFC5932]
0x00C1	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256	[RFC5932]
0x00C2	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256	[RFC5932]
0x00C3	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256	[RFC5932]
0x00C4	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256	[RFC5932]
0x00C5	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256	[RFC5932]
0xC001	TLS_ECDH_ECDSA_WITH_NULL_SHA	[RFC4492]
0xC002	TLS_ECDH_ECDSA_WITH_RC4_128_SHA	[RFC4492][RFC6347]
0xC003	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA	[RFC4492]
0xC004	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA	[RFC4492]
0xC005	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA	[RFC4492]
0xC006	TLS_ECDHE_ECDSA_WITH_NULL_SHA	[RFC4492]
0xC007	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA	[RFC4492][RFC6347]
0xC008	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA	[RFC4492]
0xC009	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA	[RFC4492]
0xC00A	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA	[RFC4492]
0xC00B	TLS_ECDH_RSA_WITH_NULL_SHA	[RFC4492]
0xC00C	TLS_ECDH_RSA_WITH_RC4_128_SHA	[RFC4492][RFC6347]
0xC00D	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA	[RFC4492]
0xC00E	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA	[RFC4492]
0xC00F	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA	[RFC4492]
0xC010	TLS_ECDHE_RSA_WITH_NULL_SHA	[RFC4492]
0xC011	TLS_ECDHE_RSA_WITH_RC4_128_SHA	[RFC4492][RFC6347]
0xC012	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA	[RFC4492]
0xC013	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA	[RFC4492]
0xC014	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA	[RFC4492]
0xC015	TLS_ECDH_anon_WITH_NULL_SHA	[RFC4492]
0xC016	TLS_ECDH_anon_WITH_RC4_128_SHA	[RFC4492][RFC6347]
0xC017	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA	[RFC4492]
0xC018	TLS_ECDH_anon_WITH_AES_128_CBC_SHA	[RFC4492]
0xC019	TLS_ECDH_anon_WITH_AES_256_CBC_SHA	[RFC4492]
0xC01A	TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA	[RFC5054]
0xC01B	TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA	[RFC5054]
0xC01C	TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA	[RFC5054]
0xC01D	TLS_SRP_SHA_WITH_AES_128_CBC_SHA	[RFC5054]
0xC01E	TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA	[RFC5054]
0xC01F	TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA	[RFC5054]
0xC020	TLS_SRP_SHA_WITH_AES_256_CBC_SHA	[RFC5054]
0xC021	TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA	[RFC5054]
0xC022	TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA	[RFC5054]
0xC023	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256	[RFC5289]
0xC024	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384	[RFC5289]
0xC025	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256	[RFC5289]
0xC026	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384	[RFC5289]
0xC027	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256	[RFC5289]
0xC028	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384	[RFC5289]
0xC029	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256	[RFC5289]
0xC02A	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384	[RFC5289]
0xC02B	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256	[RFC5289]
0xC02C	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384	[RFC5289]
0xC02D	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256	[RFC5289]
0xC02E	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384	[RFC5289]
0xC02F	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	[RFC5289]
0xC030	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	[RFC5289]
0xC031	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256	[RFC5289]
0xC032	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384	[RFC5289]
0xC033	TLS_ECDHE_PSK_WITH_RC4_128_SHA	[RFC5489][RFC6347]
0xC034	TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA	[RFC5489]
0xC035	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA	[RFC5489]
0xC036	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA	[RFC5489]
0xC037	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256	[RFC5489]
0xC038	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384	[RFC5489]
0xC039	TLS_ECDHE_PSK_WITH_NULL_SHA	[RFC5489]
0xC03A	TLS_ECDHE_PSK_WITH_NULL_SHA256	[RFC5489]
0xC03B	TLS_ECDHE_PSK_WITH_NULL_SHA384	[RFC5489]
0xC03C	TLS_RSA_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC03D	TLS_RSA_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC03E	TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC03F	TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC040	TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC041	TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC042	TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC043	TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC044	TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC045	TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC046	TLS_DH_anon_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC047	TLS_DH_anon_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC048	TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC049	TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC04A	TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC04B	TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC04C	TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC04D	TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC04E	TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC04F	TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC050	TLS_RSA_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC051	TLS_RSA_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC052	TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC053	TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC054	TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC055	TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC056	TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC057	TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC058	TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC059	TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC05A	TLS_DH_anon_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC05B	TLS_DH_anon_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC05C	TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC05D	TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC05E	TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC05F	TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC060	TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC061	TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC062	TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC063	TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC064	TLS_PSK_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC065	TLS_PSK_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC066	TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC067	TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC068	TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC069	TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC06A	TLS_PSK_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC06B	TLS_PSK_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC06C	TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC06D	TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC06E	TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256	[RFC6209]
0xC06F	TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384	[RFC6209]
0xC070	TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256	[RFC6209]
0xC071	TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384	[RFC6209]
0xC072	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256	[RFC6367]
0xC073	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384	[RFC6367]
0xC074	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256	[RFC6367]
0xC075	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384	[RFC6367]
0xC076	TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256	[RFC6367]
0xC077	TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384	[RFC6367]
0xC078	TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256	[RFC6367]
0xC079	TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384	[RFC6367]
0xC07A	TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC07B	TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC07C	TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC07D	TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC07E	TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC07F	TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC080	TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC081	TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC082	TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC083	TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC084	TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC085	TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC086	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC087	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC088	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC089	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC08A	TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC08B	TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC08C	TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC08D	TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC08E	TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC08F	TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC090	TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC091	TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC092	TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256	[RFC6367]
0xC093	TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384	[RFC6367]
0xC094	TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256	[RFC6367]
0xC095	TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384	[RFC6367]
0xC096	TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256	[RFC6367]
0xC097	TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384	[RFC6367]
0xC098	TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256	[RFC6367]
0xC099	TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384	[RFC6367]
0xC09A	TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256	[RFC6367]
0xC09B	TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384	[RFC6367]
0xC09C	TLS_RSA_WITH_AES_128_CCM	[draft-mcgrew-tls-aes-ccm-04]
0xC09D	TLS_RSA_WITH_AES_256_CCM	[draft-mcgrew-tls-aes-ccm-04]
0xC09E	TLS_DHE_RSA_WITH_AES_128_CCM	[draft-mcgrew-tls-aes-ccm-04]
0xC09F	TLS_DHE_RSA_WITH_AES_256_CCM	[draft-mcgrew-tls-aes-ccm-04]
0xC0A0	TLS_RSA_WITH_AES_128_CCM_8	[draft-mcgrew-tls-aes-ccm-04]
0xC0A1	TLS_RSA_WITH_AES_256_CCM_8	[draft-mcgrew-tls-aes-ccm-04]
0xC0A2	TLS_DHE_RSA_WITH_AES_128_CCM_8	[draft-mcgrew-tls-aes-ccm-04]
0xC0A3	TLS_DHE_RSA_WITH_AES_256_CCM_8	[draft-mcgrew-tls-aes-ccm-04]
0xC0A4	TLS_PSK_WITH_AES_128_CCM	[draft-mcgrew-tls-aes-ccm-04]
0xC0A5	TLS_PSK_WITH_AES_256_CCM	[draft-mcgrew-tls-aes-ccm-04]
0xC0A6	TLS_DHE_PSK_WITH_AES_128_CCM	[draft-mcgrew-tls-aes-ccm-04]
0xC0A7	TLS_DHE_PSK_WITH_AES_256_CCM	[draft-mcgrew-tls-aes-ccm-04]
0xC0A8	TLS_PSK_WITH_AES_128_CCM_8	[draft-mcgrew-tls-aes-ccm-04]
0xC0A9	TLS_PSK_WITH_AES_256_CCM_8	[draft-mcgrew-tls-aes-ccm-04]
0xC0AA	TLS_PSK_DHE_WITH_AES_128_CCM_8	[draft-mcgrew-tls-aes-ccm-04]
0xC0AB	TLS_PSK_DHE_WITH_AES_256_CCM_8	[draft-mcgrew-tls-aes-ccm-04]
0xFEFE	SSL_RSA_FIPS_WITH_DES_CBC_SHA	http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
0xFEFF	SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA	http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
0xFFE0	SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA	http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
0xFFE1	SSL_RSA_FIPS_WITH_DES_CBC_SHA	http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html


#define TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5          0x03000060
#define TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5      0x03000061
#define TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA         0x03000062
#define TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA     0x03000063
#define TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA          0x03000064
#define TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA      0x03000065
#define TLS1_CK_DHE_DSS_WITH_RC4_128_SHA                0x03000066
#define TLS1_CK_RSA_WITH_AES_128_SHA                    0x0300002F
#define TLS1_CK_DH_DSS_WITH_AES_128_SHA                 0x03000030
#define TLS1_CK_DH_RSA_WITH_AES_128_SHA                 0x03000031
#define TLS1_CK_DHE_DSS_WITH_AES_128_SHA                0x03000032
#define TLS1_CK_DHE_RSA_WITH_AES_128_SHA                0x03000033
#define TLS1_CK_ADH_WITH_AES_128_SHA                    0x03000034
#define TLS1_CK_RSA_WITH_AES_256_SHA                    0x03000035
#define TLS1_CK_DH_DSS_WITH_AES_256_SHA                 0x03000036
#define TLS1_CK_DH_RSA_WITH_AES_256_SHA                 0x03000037
#define TLS1_CK_DHE_DSS_WITH_AES_256_SHA                0x03000038
#define TLS1_CK_DHE_RSA_WITH_AES_256_SHA                0x03000039
#define TLS1_CK_ADH_WITH_AES_256_SHA                    0x0300003A
#define TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA           0x03000041
#define TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA        0x03000042
#define TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA        0x03000043
#define TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA       0x03000044
#define TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA       0x03000045
#define TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA           0x03000046
#define TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA           0x03000084
#define TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA        0x03000085
#define TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA        0x03000086
#define TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA       0x03000087
#define TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA       0x03000088
#define TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA           0x03000089
#define TLS1_CK_RSA_WITH_SEED_SHA                       0x03000096
#define TLS1_CK_DH_DSS_WITH_SEED_SHA                    0x03000097
#define TLS1_CK_DH_RSA_WITH_SEED_SHA                    0x03000098
#define TLS1_CK_DHE_DSS_WITH_SEED_SHA                   0x03000099
#define TLS1_CK_DHE_RSA_WITH_SEED_SHA                   0x0300009A
#define TLS1_CK_ADH_WITH_SEED_SHA                       0x0300009B
#define TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA                0x0300C001
#define TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA             0x0300C002
#define TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA        0x0300C003
#define TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA         0x0300C004
#define TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA         0x0300C005
#define TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA               0x0300C006
#define TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA            0x0300C007
#define TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA       0x0300C008
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA        0x0300C009
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA        0x0300C00A
#define TLS1_CK_ECDH_RSA_WITH_NULL_SHA                  0x0300C00B
#define TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA               0x0300C00C
#define TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA          0x0300C00D
#define TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA           0x0300C00E
#define TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA           0x0300C00F
#define TLS1_CK_ECDHE_RSA_WITH_NULL_SHA                 0x0300C010
#define TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA              0x0300C011
#define TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA         0x0300C012
#define TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA          0x0300C013
#define TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA          0x0300C014
#define TLS1_CK_ECDH_anon_WITH_NULL_SHA                 0x0300C015
#define TLS1_CK_ECDH_anon_WITH_RC4_128_SHA              0x0300C016
#define TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA         0x0300C017
#define TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA          0x0300C018
#define TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA          0x0300C019

#define SSL3_CK_SCSV                            0x030000FF

#define SSL3_CK_RSA_NULL_MD5                    0x03000001
#define SSL3_CK_RSA_NULL_SHA                    0x03000002
#define SSL3_CK_RSA_RC4_40_MD5                  0x03000003
#define SSL3_CK_RSA_RC4_128_MD5                 0x03000004
#define SSL3_CK_RSA_RC4_128_SHA                 0x03000005
#define SSL3_CK_RSA_RC2_40_MD5                  0x03000006
#define SSL3_CK_RSA_IDEA_128_SHA                0x03000007
#define SSL3_CK_RSA_DES_40_CBC_SHA              0x03000008
#define SSL3_CK_RSA_DES_64_CBC_SHA              0x03000009
#define SSL3_CK_RSA_DES_192_CBC3_SHA            0x0300000A

#define SSL3_CK_DH_DSS_DES_40_CBC_SHA           0x0300000B
#define SSL3_CK_DH_DSS_DES_64_CBC_SHA           0x0300000C
#define SSL3_CK_DH_DSS_DES_192_CBC3_SHA         0x0300000D
#define SSL3_CK_DH_RSA_DES_40_CBC_SHA           0x0300000E
#define SSL3_CK_DH_RSA_DES_64_CBC_SHA           0x0300000F
#define SSL3_CK_DH_RSA_DES_192_CBC3_SHA         0x03000010

#define SSL3_CK_EDH_DSS_DES_40_CBC_SHA          0x03000011
#define SSL3_CK_EDH_DSS_DES_64_CBC_SHA          0x03000012
#define SSL3_CK_EDH_DSS_DES_192_CBC3_SHA        0x03000013
#define SSL3_CK_EDH_RSA_DES_40_CBC_SHA          0x03000014
#define SSL3_CK_EDH_RSA_DES_64_CBC_SHA          0x03000015
#define SSL3_CK_EDH_DSS_DES_40_CBC_SHA          0x03000011
#define SSL3_CK_EDH_DSS_DES_64_CBC_SHA          0x03000012
#define SSL3_CK_EDH_DSS_DES_192_CBC3_SHA        0x03000013
#define SSL3_CK_EDH_RSA_DES_40_CBC_SHA          0x03000014
#define SSL3_CK_EDH_RSA_DES_64_CBC_SHA          0x03000015
#define SSL3_CK_EDH_RSA_DES_192_CBC3_SHA        0x03000016

#define SSL3_CK_ADH_RC4_40_MD5                  0x03000017
#define SSL3_CK_ADH_RC4_128_MD5                 0x03000018
#define SSL3_CK_ADH_DES_40_CBC_SHA              0x03000019
#define SSL3_CK_ADH_DES_64_CBC_SHA              0x0300001A
#define SSL3_CK_ADH_DES_192_CBC_SHA             0x0300001B

#define SSL3_CK_FZA_DMS_NULL_SHA                0x0300001C
#define SSL3_CK_FZA_DMS_FZA_SHA                 0x0300001D
#define SSL3_CK_FZA_DMS_RC4_SHA                 0x0300001E

#define SSL3_CK_KRB5_DES_64_CBC_SHA             0x0300001E
#define SSL3_CK_KRB5_DES_192_CBC3_SHA           0x0300001F
#define SSL3_CK_KRB5_RC4_128_SHA                0x03000020
#define SSL3_CK_KRB5_IDEA_128_CBC_SHA           0x03000021
#define SSL3_CK_KRB5_DES_64_CBC_MD5             0x03000022
#define SSL3_CK_KRB5_DES_192_CBC3_MD5           0x03000023
#define SSL3_CK_KRB5_RC4_128_MD5                0x03000024
#define SSL3_CK_KRB5_IDEA_128_CBC_MD5           0x03000025

#define SSL3_CK_KRB5_DES_40_CBC_SHA             0x03000026
#define SSL3_CK_KRB5_RC2_40_CBC_SHA             0x03000027
#define SSL3_CK_KRB5_RC4_40_SHA                 0x03000028
#define SSL3_CK_KRB5_DES_40_CBC_MD5             0x03000029
#define SSL3_CK_KRB5_RC2_40_CBC_MD5             0x0300002A
#define SSL3_CK_KRB5_RC4_40_MD5                 0x0300002B

#define SSL2_CK_NULL_WITH_MD5                   0x02000000 /* v3 */
#define SSL2_CK_RC4_128_WITH_MD5                0x02010080
#define SSL2_CK_RC4_128_EXPORT40_WITH_MD5       0x02020080
#define SSL2_CK_RC2_128_CBC_WITH_MD5            0x02030080
#define SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5   0x02040080
#define SSL2_CK_IDEA_128_CBC_WITH_MD5           0x02050080
#define SSL2_CK_DES_64_CBC_WITH_MD5             0x02060040
#define SSL2_CK_DES_64_CBC_WITH_SHA             0x02060140 /* v3 */
#define SSL2_CK_DES_192_EDE3_CBC_WITH_MD5       0x020700c0
#define SSL2_CK_DES_192_EDE3_CBC_WITH_SHA       0x020701c0 /* v3 */
#define SSL2_CK_RC4_64_WITH_MD5                 0x02080080 /* MS hack */
 
#define SSL2_CK_DES_64_CFB64_WITH_MD5_1         0x02ff0800 /* SSLeay */
#define SSL2_CK_NULL                            0x02ff0810 /* SSLeay */

";

my %nameofcc;
my %numberofcc;
foreach my $line (split "\n", $ciphersuitenamestring) {
	if ($line =~ /(?:SSL3|TLS1)_CK_(\S+)\s+0x0300([0-9A-Fa-f]{4})/) {
		$nameofcc{$2} = $1;
		$numberofcc{$1} = $2;
	}
	if ($line =~ /SSL2_CK_(\S+)\s+0x02([0-9A-Fa-f]{6})/) {
		$nameofcc{uc $2} = $1;
		$numberofcc{$1} = uc $2;
	}
	if ($line =~ /^0x([0-9a-fA-F]{4})\s+(?:SSL|TLS)_(\S+)/) {
		$nameofcc{uc $1} = $2;
		$numberofcc{$2} = uc $1;
	}
}
my $starttime = time;
printf "Starting ssl-cipher-enum v%s ( http://labs.portcullis.co.uk/application/ssl-cipher-suite-enum/ ) at %s\n", $VERSION, scalar(localtime);
print "\n";
print "Target: $host\n";
print "IP:     $ip\n";
print "Port:   $port\n";
print "\n";

protocol: foreach my $protocol ("0200", "0300", "0301", "0302", "0303") {
	my $protocol_name = get_protocol_name($protocol);
	print "\n[+] Testing protocol $protocol_name\n\n";
	my $cc_supported = 0;
	if ($protocol eq "0200") {
		foreach my $ciphersuite (qw(000000 010080 020080 030080 040080 050080 060040 060140 0700c0 0701c0 080080 ff0800 ff0810 0000ff)) {
			printf "[D] Checking Cipher Suite: %s %s [%s]\n", get_protocol_name($protocol), get_cc_name($ciphersuite), $ciphersuite if $debug > 0;
			print "[+] Connecting to $host:$port\n" if $debug > 1;
			my $socket = get_socket();
			my $string = get_client_hello_v2($ciphersuite);	

			# send client hello
			print "[+] Sending:\n"  if $debug > 1;
			hdump($string) if $debug > 1;
			print $socket $string;
			
			# recv server hello (or alert).  first read length of packet
			my $data;
			$socket->recv($data,2);
			print "[+] Received from Server :\n"  if $debug > 1;
			hdump($data) if $debug > 1;
			
			my @data = split("", $data);
			if (scalar(@data) > 0) {
				my $length = ((ord($data[0]) & 0x7f) << 8) + ord($data[1]);
				printf "[+] Initial length: %d\n", $length if $debug > 1;
				my $data2;
				$socket->recv($data2,$length);
				print "[+] Received from Server :\n" if $debug > 1;
				hdump($data2) if $debug > 1;
				$data = $data . $data2;
				@data = split("", $data);

				printf "[+] Handshake message type (should be 4): %02x\n", ord($data[2]) if $debug > 1;
				printf "[+] Protocol: %d.%d\n", ord($data[6]), ord($data[5]) if $debug > 1;
				my $cs_len = sprintf "%02x%02x", ord($data[9]), ord($data[10]);
				printf "[+] Cipher spec length (should be 3): %02x%02x\n", ord($data[9]), ord($data[10]) if $debug > 1;
				if ($cs_len eq "0003") {
					my $cc = sprintf "%02x%02x%02x", ord($data[-19]), ord($data[-18]), ord($data[-17]);
					printf "[+] Cipher suite: %s [%02x%02x%02x]\n", get_cc_name($cc), ord($data[-19]), ord($data[-18]), ord($data[-17]);
				} else {
					print "[+] Unknown response.  Cipher spec length was 0\n";
				}
			} else {
				printf "[+] Cipher suite not supported (truncated packet): %s, cipher suite %s [%s]\n", get_protocol_name($protocol), get_cc_name($ciphersuite), $ciphersuite if $debug > 0;
			}
		}
	} else {
		my @cc_todo_individually = ();
		my @cc_todo_in_groups = ();

		# Put the rarely-supported cipher suites into one group
		# and the more commonly supported ones into another
		foreach my $ciphersuite (map {sprintf("00%02x", $_), sprintf("c0%02x", $_); } (0..255)) {
			my $cc_name = get_cc_name($ciphersuite);
			if ($cc_name =~ /(UNKNOWN|PSK|GOST|KRB|NULL|anon|FZA|ADH)/) {
				push @cc_todo_in_groups, $ciphersuite;
			} else {
				push @cc_todo_individually, $ciphersuite;
			}
		}

		my $cc_chunk_size = 10;
		my $protocol_supported = 1;
		while (scalar @cc_todo_in_groups) {
			my @cc_chunk = ();
			chunk: for (1..$cc_chunk_size) {
				if (scalar @cc_todo_in_groups) {
					push @cc_chunk, pop @cc_todo_in_groups;
				}
			}
			if (scalar @cc_chunk) {
				my $supported = test_v3_ciphersuites($protocol, @cc_chunk);
				if ($supported == 1) {
					# one or more is valid.  so we try individually instead later
					push @cc_todo_individually, @cc_chunk;
				} elsif ($supported == 2) {
					$protocol_supported = 0;
					last;
				} elsif ($supported == 0) {
					# none are valid.  we saved time by not trying individually
				}
			}
		}

		if ($protocol_supported) {
			foreach my $ciphersuite (@cc_todo_individually) {
				my $supported = test_v3_ciphersuites($protocol, $ciphersuite);
				if ($supported == 1) {
					$cc_supported++;
				}
			}
		}
	}
	printf "\n[+] %s %s cipher suites supported\n", $cc_supported, get_protocol_name($protocol);
}

print "\n";
printf "[+] ssl-cipher-enum v%s completed after %s secs at %s\n", $VERSION, time - $starttime, scalar(localtime);
print "\n";

sub get_cc_name {
	my ($ciphersuite) = @_; # in hex
	my $ccname = "UNKNOWN_CIPHER_SUITE_NAME [$ciphersuite]";
	if (defined($nameofcc{uc $ciphersuite})) {
		$ccname = $nameofcc{uc $ciphersuite} . "[" . $ciphersuite . "]";
	}
	return $ccname;
}

# http://www.perlmonks.org/?node_id=111481
sub hdump {
    my $offset = 0;
    my(@array,$format);
    foreach my $data (unpack("a16"x(length($_[0])/16)."a*",$_[0])) {
        my($len)=length($data);
        if ($len == 16) {
            @array = unpack('N4', $data);
            $format="0x%08x (%05d)   %08x %08x %08x %08x   %s\n";
        } else {
            @array = unpack('C*', $data);
            $_ = sprintf "%2.2x", $_ for @array;
            push(@array, '  ') while $len++ < 16;
            $format="0x%08x (%05d)" .
               "   %s%s%s%s %s%s%s%s %s%s%s%s %s%s%s%s   %s\n";
        } 
        $data =~ tr/\0-\37\177-\377/./;
        printf $format,$offset,$offset,@array,$data;
        $offset += 16;
    }
}

sub get_protocol_name {
	my ($number) = @_;
	return "SSLv2.0" if $number eq "0200";
	return "SSLv3.0" if $number eq "0300";
	return "TLSv1.0" if $number eq "0301";
	return "TLSv1.1" if $number eq "0302";
	return "TLSv1.2" if $number eq "0303";
	return "UNKNOWN_PROTOCOL_$number";
}

sub get_client_hello_v2 {
	my (@ciphersuites_hex) = @_;
	my $ciphersuites_hex = join("", @ciphersuites_hex);
	my @packet_hex;
	push @packet_hex, qw(80); # bit 1: 2 byte header; bit 2: no security escapes, bits 3-8: high length bits
	push @packet_hex, sprintf("%02x", 0x1c + length($ciphersuites_hex) / 2);
	push @packet_hex, qw(01); # client hello
	push @packet_hex, qw(0002); # version 2.0
	push @packet_hex, sprintf("%04x", length($ciphersuites_hex) / 2);
	push @packet_hex, qw(0000); # session id length
	push @packet_hex, qw(0010); # challenge length
	push @packet_hex, $ciphersuites_hex . "001122"; #  TODO what's this 1122 bit?
	my $r = "";
	for (1..16) {
		my $rand = sprintf "%02x", int(rand(255));
		$r .= $rand;
	}
	push @packet_hex, $r; # challenge
	my $string = join("", @packet_hex);
	$string =~ s/(..)/sprintf("%c", hex($1))/ge;

	return $string;
}

sub get_client_hello_v3 {
	my ($protocol, @ciphersuites_hex) = @_;
	my $ciphersuites_hex = join("", @ciphersuites_hex);
	my @packet_hex;
	push @packet_hex, qw(16); # content type: handshake (22)
	push @packet_hex, $protocol;
	push @packet_hex, sprintf("%04x", 0x56 + length($ciphersuites_hex) / 2);
	push @packet_hex, qw(01); # client hello
	# push @packet_hex, qw(00 00 54); # length
	push @packet_hex, sprintf("%06x", 0x52 + length($ciphersuites_hex) / 2);
	push @packet_hex, $protocol;
	push @packet_hex, qw(4f de d1 b9); # time
	push @packet_hex, qw(e4 60 78 36 ad fb d6  26 bb f3 0f b5 0d 6c e0 cf 8f 34 06 28 03 93 2e  cf 24 29 38 ff); # random
	push @packet_hex, qw(00); # session id length
	push @packet_hex, sprintf("%04x", length($ciphersuites_hex) / 2);
	push @packet_hex, $ciphersuites_hex;
	push @packet_hex, qw(02); # compression methods length
	push @packet_hex, qw(01); # compression: deflate
	push @packet_hex, qw(00); # compression: null
	push @packet_hex, qw(00 28); # extensions length
	push @packet_hex, qw(ff 01); # reneg info
	push @packet_hex, qw(00 01); # length
	push @packet_hex, qw(00); # data
	push @packet_hex, qw(00 0a); # elliptic curves
	push @packet_hex, qw(00 08); # length
	push @packet_hex, qw(00 06); # ec length
	push @packet_hex, qw(00 17 00 18 00 19); # list of ec's - each 2 bytes
	push @packet_hex, qw(00 0b); # ec point formats
	push @packet_hex, qw(00 02); # length
	push @packet_hex, qw(01); # ec pf length
	push @packet_hex, qw(00); # ec pf uncompressed
	push @packet_hex, qw(00 23); # session ticket tls
	push @packet_hex, qw(00 00); # length
	push @packet_hex, qw(33 74); # unknown type
	push @packet_hex, qw(00 00); # length
	push @packet_hex, qw(00 05); # status request
	push @packet_hex, qw(00 05); # length
	push @packet_hex, qw(01 00 00 00 00); # data
		
	my $string = join("", @packet_hex);
	$string =~ s/(..)/sprintf("%c", hex($1))/ge;
	return $string;
}

sub get_socket {
	my $socket = new IO::Socket::INET (
		PeerHost => $ip,
		PeerPort => $port,
		Proto => 'tcp',
	) or die "ERROR in Socket Creation : $!\n";
	return $socket;
}

# test_v3_cipher_suites:
#  arg1: protocol e.g. "0301"
#  arg2: list of cipher suites, e.g. ("0011", "C022")
# returns:
#  2 if server doesn't support the protocol
#  1 if one of the supplied ciphersuites if valid
#  0 if none are valid
sub test_v3_ciphersuites {
	my ($protocol, @ciphersuites) = @_;
	printf "[D] Checking Cipher Suites: %s %s\n", get_protocol_name($protocol), join(",", map { get_cc_name($_) } @ciphersuites) if $debug > 0;
	print "[+] Connecting to $host:$port\n" if $debug > 1;
	my $socket = get_socket();
	
	my $string = get_client_hello_v3($protocol, @ciphersuites);
	my $protocol_bin = $protocol;
	$protocol_bin =~ s/\s//g;
	$protocol_bin =~ s/(..)/sprintf("%c", hex($1))/ge;
	
	print "[+] Sending:\n" if $debug > 1;
	hdump($string) if $debug > 1;
	
	print $socket $string;
	
	my $data;
	$socket->recv($data,5);
	print "[+] Received from Server :\n" if $debug > 1;
	hdump($data) if $debug > 1;

	my $ccname = join(",", map { get_cc_name($_) } @ciphersuites);
	my @data = split("", $data);
	if (scalar(@data) > 0) {
		my $length = (ord($data[3]) << 8) + ord($data[4]);
		printf "[+] Initial length: %d\n", $length if $debug > 1;
		my $data2;
		$socket->recv($data2,$length);
		print "[+] Received from Server :\n" if $debug > 1;
		hdump($data2) if $debug > 1;
		$data = $data . $data2;
		@data = split("", $data);

		if ($data[1] . $data[2] ne $protocol_bin) {
			printf "[+] Protocol %s is not supported.  Skipping.\n", get_protocol_name($protocol);
			return 2;
		}
		if ($data[0] eq "\x15") {
			if ($data[6] eq "\x28") {
				printf "[+] Cipher suite NOT supported.  Probed for %s %s, Reply protocol: %s\n", get_protocol_name($protocol), $ccname, ord($data[1]) . "." . ord($data[2]) if $debug > 0;
			} else {
				printf "[+] Packet type 'Alert' for protocol %s cipher suite %s: %02x\n", $protocol, $ccname, ord($data[0]);
				printf "[+] Protocol: %d.%d\n", ord($data[1]), ord($data[2]) if $debug > 1;
				printf "[+] Alert Level (2 is fatal): %02x\n", ord($data[5]) if $debug > 1;
				printf "[+] Alert description (0x28 is Handshake failure): %02x\n", ord($data[6]) if $debug > 1;
			}

		} elsif ($data[0] eq "\x16") {
			my $sidlen = ord($data[43]);
			my $ccpos = $sidlen + 44;
			my $neg_cc = sprintf("%02x%02x",ord($data[$ccpos]), ord($data[$ccpos+1]));
			my $neg_cc_name = get_cc_name($neg_cc);
			printf "[+] Cipher suite supported.  Probed for: %s %s [%s], Negotiated: %s\n", get_protocol_name($protocol), $ccname, get_protocol_name(sprintf("%02x%02x", ord($data[1]), ord($data[2]))), $neg_cc_name;
			printf "[+] packet type (should be 0x02 for Server Hello): %02x\n", ord($data[5]) if $debug > 1;
			printf "[+] Cipher Suite: %02x%02x\n", ord($data[44]), ord($data[45]) if $debug > 1;
			return 1;
		} else {
			printf "[+] Packet type (should be 0x16) for protocol %d.%d, cipher suite %s: %02x\n", ord($data[1]), ord($data[2]), $ccname, ord($data[0]);
		printf "[+] Protocol: %d.%d\n", ord($data[1]), ord($data[2]);
			printf "[+] packet type (should be 0x02 for Server Hello): %02x\n", ord($data[5]);
			printf "[+] Protocol2: %d.%d\n", ord($data[9]), ord($data[10]);
			printf "[+] Server time: %02x%02x%02x%02x\n", ord($data[11]), ord($data[12]), ord($data[13]), ord($data[14]);
			printf "[+] Cipher Suite: %02x%02x\n", ord($data[44]), ord($data[45]);
			printf "[+] Compression: %02x\n", ord($data[46]);
		}
	}
	return 0;
}
