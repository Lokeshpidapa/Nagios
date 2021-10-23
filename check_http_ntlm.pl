#!/usr/bin/perl
#       02/Feb/10                       nagios@sanxiago.com
#  check_http page for IIS servers with ntlm authentication
#
# 2015-07-27
#
# this check receives a URL as a parameter, logins to the IIS server
# using the curl binary, then it parses the output of the command
# and captures the response code. Timeout pass and user values are currently hardcoded
# script currently only has handlers for some response codes, but a switch was used to 
# add more in an easy way. Response code is found with regexp /HTTP\/1\.1 ([0-9]{3}) .*/

use strict;
use Switch;
use Getopt::Long;
use Time::HiRes qw ( time );
use vars qw($opt_V $opt_D $opt_h $opt_t $hostname $user $pass $agent $uri $string $verbose $PROGNAME);
use lib "/usr/local/nagios/libexec" ;
use utils qw(%ERRORS &print_revision &support &usage);
my ($state, $statetext, $size, $perf, $time, $start, $text_matched, $nottext_matched);
my ($pid, $outputsize, $timeout, $authentication_sent, $output, $http_code, $command);

$PROGNAME="check_http_ntlm.pl";

sub print_help ();
sub print_usage ();

my $DEBUG = 0;

my ($opt_V, $opt_h, $hostname, $port, $user, $pass, $secure, $certignore, $uri);
my ($string, $notstring, $warning, $critical, $opt_t, $proxy, $header, $message);

Getopt::Long::Configure('bundling');
GetOptions
  ("V"   => \$opt_V,      "version"     => \$opt_V,
   "D"   => \$opt_D,      "DEBUG"       => \$opt_D,
   "h"   => \$opt_h,      "help"        => \$opt_h,
   "H=s" => \$hostname,   "hostname=s"  => \$hostname,
   "p=i" => \$port,       "port=i"      => \$port,
   "U=s" => \$user,       "user=s"      => \$user,
   "P=s" => \$pass,       "pass=s"      => \$pass,
   "A=s" => \$agent,      "agent=s"     => \$agent,
   "S"   => \$secure,     "secure"      => \$secure,
   "k"   => \$certignore, "certignore"  => \$certignore,
   "u=s" => \$uri,        "uri=s"       => \$uri,
   "e=s" => \$header,     "header=s"    => \$header,
   "s=s" => \$string,     "string=s"    => \$string,
   "q=s" => \$notstring,  "notstring=s" => \$notstring,
   "w=s" => \$warning,    "warning=s"   => \$warning,
   "c=s" => \$critical,   "critical=s"  => \$critical,
   "t=i" => \$opt_t,      "timeout=i"   => \$opt_t,
   "x=s" => \$proxy,      "proxy=s"     => \$proxy);

if ($opt_V) {
  print_revision($PROGNAME,'$Revision: 2.5 $');
  exit $ERRORS{'OK'};
}

if ($opt_h) {
  print_help();
  exit $ERRORS{'OK'};
}

if ($opt_D) {
  $DEBUG = 1;
}

# construct the syntax for curl based upon parameters supplied
my $curlsyntax = "curl";

# To make output more useful
my $testurl = "";

if ((defined $user) && (!defined $pass)) {
  print "Password is missing\n";
  print_usage();
  exit $ERRORS{'UNKNOWN'};
}

if ((!defined $user) && (defined $pass)) {
  print "Username is missing\n";
  print_usage();
  exit $ERRORS{'UNKNOWN'};
}

if ((defined $user) && (defined $pass)) {
  $curlsyntax = $curlsyntax . " -u " . $user . ":" . $pass . " --ntlm";
}

if ($certignore) {
  $curlsyntax = $curlsyntax . " -k";
}

if (defined $proxy) {
  $curlsyntax = $curlsyntax . " -x " . $proxy;
}

if (defined $agent) {
  $curlsyntax = $curlsyntax . " -A '$agent'";
} else {
  $curlsyntax = $curlsyntax . " -A 'Mozilla/4.0'";
}

if (($secure) && (defined $port)) {
  $secure = "https";
  $port = ":" . $port;
} elsif (($secure) && (!defined $port)) {
  $secure = "https";
  $port = "";
} elsif ((!$secure) && (defined $port)) {
  $secure = "http";
  $port = ":" . $port;
} else {
  $secure = "http";
  $port = "";
}

unless (defined $uri) {
  $uri = "/";
}

unless (defined $hostname) {
  print "Hostname is missing\n";
  print_usage();
  exit $ERRORS{'UNKNOWN'};
} else {
  #$curlsyntax = $curlsyntax . " --stderr /dev/null " . $secure . "://" . $hostname . $port . $uri . " -i";
  $curlsyntax = $curlsyntax . " --stderr /dev/null -i " . $secure . "://" . $hostname . $port . $uri;
}

unless (defined $string) {
  $string = undef;
}

unless (defined $notstring) {
  $notstring = undef;
}

unless (defined $warning) {
  $warning = 4;      # default warning threshold
}

unless (defined $critical) {
  $critical = 8;      # default critical threshold
}

unless (defined $opt_t) {
  $opt_t = $utils::TIMEOUT ;      # default timeout
}

# Just in case of problems, let's not hang Nagios
$SIG{'ALRM'} = sub {
  print "HTTP Timeout: No Answer from Client\n";
  exit $ERRORS{'CRITICAL'};
};
alarm($opt_t);

print "curlsyntax is $curlsyntax \n" if $DEBUG;
$testurl = $secure . "://" . $hostname . $port . $uri;

# Construct message text but also a clickable link using syntax like this
$message = "(Testing <A HREF=\"$testurl\" TARGET=\"_tab\">$testurl</A>)";

$start = Time::HiRes::time();
run_command($curlsyntax);
$time = sprintf("%.2f",Time::HiRes::time()-$start);

# Performance data
$perf = "time=" . $time . "s;" . $warning . ";" . $critical . ";0 size=" . $size . "KB;;;0 ";

if ((defined $string) && (!$text_matched)) {
  $output = 'Text not found - expected "' . $string . '"';
  print "string match - output is $output http_code is $http_code\n" if $DEBUG;
  print "HTTP $http_code $message $output - $time second response time|$perf\n";
  exit $ERRORS{'CRITICAL'};
}

if ((defined $notstring) && ($nottext_matched)) {
  $output = 'Text was found - did not expect "' . $notstring . '"';
  print "notstring match - output is $output http_code is $http_code\n" if $DEBUG;
  print "HTTP $http_code $message $output - $time second response time|$perf\n";
  exit $ERRORS{'CRITICAL'};
}

switch ($http_code){
  case 200 {
    if ($time >= $critical) {
      $state = 2;
      $statetext = "CRITICAL";
    } elsif ($time >= $warning) {
      $state = 1;
      $statetext = "WARNING";
    } else {
      $state = 0;
      $statetext = "OK";
    }
    print "HTTP $statetext $message - $time second response time|$perf\n";
    exit($state);
  }
  case 302 {
    if ($header == 302) {
      if ($time >= $critical) {
        $state = 2;
        $statetext = "CRITICAL";
      } elsif ($time >= $warning) {
        $state = 1;
        $statetext = "WARNING";
      } else {
        $state = 0;
        $statetext = "OK";
      }
      print "HTTP $statetext $message - $time second response time|$perf\n";
      exit($state);
    } else {
      print "HTTP PAGE MOVED $message - $time second response time|$perf\n";
      exit $ERRORS{'WARNING'};
    }
  }
  case 403 {
    if ($header == 403) {
      if ($time >= $critical) {
        $state = 2;
        $statetext = "CRITICAL";
      } elsif ($time >= $warning) {
        $state = 1;
        $statetext = "WARNING";
      } else {
        $state = 0;
        $statetext = "OK";
      }
      print "HTTP $statetext $message - $time second response time|$perf\n";
      exit($state);
    } else {
      print "HTTP FORBIDDEN $message - $time second response time|$perf\n";
      exit $ERRORS{'CRITICAL'};
    }
  }
  case 404 {
    if ($header == 404) {
      if ($time >= $critical) {
        $state = 2;
        $statetext = "CRITICAL";
      } elsif ($time >= $warning) {
        $state = 1;
        $statetext = "WARNING";
      } else {
        $state = 0;
        $statetext = "OK";
      }
      print "HTTP $statetext $message - $time second response time|$perf\n";
      exit($state);
    } else {
      print "HTTP PAGE NOT FOUND $message - $time second response time|$perf\n";
      exit $ERRORS{'CRITICAL'};
    }
  }
  case 500 {
    print "HTTP SERVER ERROR $message - $time second response time|$perf\n";
    exit $ERRORS{'CRITICAL'};
  }
  case 401 {
    if ($header == 401) {
      if ($time >= $critical) {
        $state = 2;
        $statetext = "CRITICAL";
      } elsif ($time >= $warning) {
        $state = 1;
        $statetext = "WARNING";
      } else {
        $state = 0;
        $statetext = "OK";
      }
      print "HTTP $statetext Unauthorized is expected - $message - $time second response time|$perf\n";
      exit($state);
    } else {
      print "ERROR $output $message - $time second response time|$perf\n";
      exit $ERRORS{'CRITICAL'};
    }
  }
}

sub run_command {
  $command=shift;
  print $command . "\n" if $DEBUG;
  $pid = open(PIPE, "$command  |") or die $!;
  eval {
    $outputsize = "";
    local $SIG{ALRM} = sub { die "TIMEDOUT" };
    alarm($timeout);
    while (<PIPE>) {
      if ($_ =~ /HTTP\/1\.\d ([0-9]{3}) .*/) {
        $http_code = $1;
        print "http code is $http_code \n" if $DEBUG;
      }
      if ((defined $string) && ($_ =~ /$string/)) {
        $text_matched = 1;
        print "text matched is $_ \n" if $DEBUG;
      }
      if ((defined $notstring) && ($_ =~ /$notstring/)) {
        $nottext_matched = 1;
      }
      $outputsize = $outputsize.$_;
      $size = length($outputsize) / 1000;
      print $_ . "\n" if $DEBUG;
    }
    close(PIPE);
  };
  if ($@) {
    die $@ unless $@ =~ /TIMEDOUT/;
    print "TIMEOUT";
    kill 9, $pid;
    $? ||= 9;
    exit $ERRORS{'CRITICAL'};
  }
}

# Usage sub
sub print_usage () {
        print "Usage: $PROGNAME
        -V, --version
        -h, --help
        -H, --hostname [Hostname]
        [-p], --port [default is 80]
        [-U], --user [Username]
        [-P], --pass [Password]
        [-S], --secure
        [-A], --user-agent [string - default is Mozilla/4.0]
        [-k], --certignore
        [-u], --uri [URI - default is /]
        [-e], --header [HTTP Code]
        [-s], --string [string]
        [-q], --notstring [string]
        [-w], --warning [threshold]
        [-c], --critical [threshold]
        [-t], --timeout [timout seconds]
        [-x], --proxy [Proxy:Port]\n";
}

# Help sub
sub print_help () {
        print_revision($PROGNAME,'$Revision: 1.0 $');

        print_usage();
        print "
-V, --Version
   Print version of plugin
-h, --help
   Print help
-H, --hostname
   Hostname to run test against
-U, --user
   NTLM Username credential for Pass Thru authentication
-P, --pass
   NTLM Password
-S, --secure
   use https versus the default http
-A, --user-agent
   pass a browser identification string to the web server - default is Mozilla/4.0
-k, --certignore
   Ignore any certificate errors
-u, --uri
   URI web page to test - default is /
-e, --header
   HTTP Code required in the header
-s, --string
   String required on the page body
-q, --notstring
   String should not appear on the page body
-w, --warning Threshold
   Warning threshold for time to test
-c, --critical Threshold
   Critical threshold for time to test
-t, --timeout
   Script timeout
-x, --proxy FQDN:Port
   Proxy server name and port like proxy.domain.com:8080
";

}

