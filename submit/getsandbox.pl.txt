#!/usr/bin/perl
####################################
# CWSandbox retrieval script       #
# SURFids 3.00                     #
# Changeset 001                    #
# 13-09-2007                       #
# Jan van Lith & Kees Trippelvitz  #
# Dave De Coster (Mods for CWS)    #
####################################

###############################################
# Changelog:
# 001 version 3.00
###############################################

####################
# Modules used
####################
use DBI;
use Mail::POP3Client;
use IO::Socket::SSL;
use MIME::Parser;
use Encode;
use MIME::QuotedPrint;
use LWP::UserAgent;
use HTML::Entities;

####################
# Variables used
####################
do '/etc/surfnetids/surfnetids-log.conf';

####################
# Main script
####################
$pop = new Mail::POP3Client(    USER     => $c_mail_username,
                                PASSWORD => $c_mail_password,
                                HOST     => $c_mail_mailhost,
                                PORT     => $c_mail_port,
                                USESSL   => $c_mail_usessl,
                                DEBUG    => 0,
                           );


# if no msgs just exit
if (($pop->Count()) < 1) {
  print "No messages...\n";
  exit;
}

$dbh = DBI->connect($c_dsn, $c_pgsql_user, $c_pgsql_pass)
       or die $DBI::errstr;

# if msgs, tell how many
print $pop->Count() . " messages found!\n";

# loop over msgs
for ($i = 1; $i <= $pop->Count(); $i++) {
  $mailfile="$c_cwtemp/mail$i";
  $xml="$c_cwtemp/xml$i";
  foreach ( $pop->Head($i) ) {
    if ($_ =~ /.*Subject:.*/) {
      @subject = split(/:/, $_);
      $subject = $subject[1];
    }
  }
  chomp($subject);
  print "subject: $subject\n";

  if ($subject eq " [SANDBOX] Uploaded from web") {
    print "Found Norman sandbox report!\n";
    ################################
    # Norman Sandbox
    ################################
    $body = $pop->Body($i) . "\n";
    open(LOG, "> $mailfile");
    print LOG "$body";
    close(LOG);
    $count = `cat $mailfile | wc -l`;
    $count = $count - 27;
    $body = `tail -n $count $mailfile`;
    $body =~ s/'/ /g;
    $body =~ s/\\/\\\\/g;
    open(LOG, "> $mailfile");
    print LOG "$body";
    close(LOG);
    $count2 = `cat $mailfile | wc -l`;
    $count2 = $count2 - 4;
    $body = `head -n $count2 $mailfile`;

    $md5 = `cat $mailfile |grep "MD5 hash:" | awk -F: '{print \$2}' |awk -F. '{print \$1}'`;
    $subject =~ s/^\s+//;
    $md5 =~ s/^\s+//;
    chomp($md5);
    
    if ("$md5" eq "") {
      # Skip this one
      next;
    } else {
      print "md5: $md5\n";
    }
    
    $body = encode("utf8", $body);
    
    ## Get all binid that are already logged
    $sth_binid = $dbh->prepare("SELECT binid FROM norman");
    $execute_result = $sth_binid->execute();
    $hash_refnorman = $sth_binid->fetchall_hashref('binid');
    
    $sth_md5 = $dbh->prepare("SELECT id FROM uniq_binaries WHERE name='$md5'");
    $execute_result = $sth_md5->execute();
    $numrows_md5 = $sth_md5->rows;
    @bin_id = $sth_md5->fetchrow_array;
    $bin_id = $bin_id[0];
       
    if ($numrows_md5 == 0) {
      print "Adding md5: $md5 into uniq_binaries table\n";
      $sth_putmd5 = $dbh->prepare("INSERT INTO uniq_binaries (name) VALUES ('$md5')");
      $execute_result = $sth_putmd5->execute();
      $sth_md5 = $dbh->prepare("SELECT id FROM uniq_binaries WHERE name='$md5'");
      $execute_result = $sth_md5->execute();
      $numrows_md5 = $sth_md5->rows;
      @bin_id = $sth_md5->fetchrow_array;
      $bin_id = $bin_id[0];
    }
    if (!exists $hash_refnorman->{ $bin_id }) {
    	print "Adding new norman result info for binary ID: $bin_id\n";
    	$sth_putnorman = $dbh->prepare("INSERT INTO norman (binid, result) VALUES ('$bin_id', '$body')");
    	$execute_result = $sth_putnorman->execute();
    } else {
    	print "Norman report of binary ID: $bin_id already logged\n";
    }
  } elsif ($subject =~ m/CWSandbox/) {
    print "Found CWSandbox report!\n";
    ################################
    # CWSandbox
    ################################
    $body = $pop->HeadAndBody($i) . "\n";
    open(LOG, "> $mailfile");
    print LOG "$body";
    close(LOG);
    
    # Rip the XML attachment out
    mimeextract($body);

    if (-e "$xml") {
      $md5 = `cat $xml | grep -m 1 md5 | cut -d \" \" -f 6 | egrep '^md5' | awk -F \"=\" '{print \$2}'`;
      $subject =~ s/^\s+//;
      $md5 =~ s/\"//g;
      chomp($md5);
      $xmlattach = 1;
    } else {
      $md5 = `cat $mailfile |grep "Submitted file" |awk -F"nepenthes" '{print \$2}'`;
      $md5 = substr($md5, 0,32);
      chomp($md5);
      $xmlattach = 0;
    }
   
    if ("$md5" eq "") {
      # Skip this one
      next;
    } else {
      print "md5: $md5\n";
    }
    if ($xmlattach == 1) { 
      $body = `$c_xalanbin -in $xml -xsl $c_surfidsdir/include/ViewAnalysis.xslt`;
      $body =~ s/'/ /g;
      $body =~ s/\\/\\\\/g;
      $body =~ s/\n+/\n/g;
      $xml2 = `cat $xml`;
      $xml2 =~ s/'/ /g;
      $xml2 =~ s/\\/\\\\/g;
    
      open(LOG, "> $mailfile");
      print LOG "$body";
      close(LOG);
    
      # This helps remove non-UTF8 characters that make postgres unhappy
      $body2 = encode("utf8", $body);
      $logit = 1; 
    } else {
      $body = `cat $mailfile |tail -n10`; 
      $body = decode_qp($body);
      open(LOG, "> $mailfile");
      print LOG "$body";
      close(LOG);
      $body = `cat $mailfile |grep "You can find the report at http:" | awk -F"report at " '{print \$2}' | awk -F"---" '{print \$1}'`;
      if ("$body" ne "") {
        $link = encode("utf8", $body);
	chomp($link);
        chop($link);

	$ua = LWP::UserAgent->new;
	$ua->agent("MyApp/0.1 ");

	my $req = HTTP::Request->new(POST => "$link");
	$req->content_type('application/x-www-form-urlencoded');

	#Pass request to the user agent and get a response back
	my $res = $ua->request($req);
	$found = 0;
	#Ceck the outcome of the response
	if ($res->is_success) {
 	 $page = $res->content;
  	 @lines = split("\n", $page);
  	 foreach $line (@lines) {
    	    if ($line =~ /liverow/) {
               $found = 1;
            } 
     	    if ($line =~ /CWSandbox/ && $found == 1) {
               $found = 2;
            }
            if ($line =~ /a href=/ && $found == 2) {
     	       chomp($line);
	       @newlink = split('\"', $line);
	       foreach $newlink (@newlink){
	          if ($newlink =~ /id/){
	      	     decode_entities($newlink);
		     $link = $newlink;
	          }
	       }
	       $found = 0;
            }
         }
        }
	else {
 	   $logit = 0;
	}
	$link =~ s/details/analysis&format=xml/;
	$link = "http://cwsandbox.org/$link";
        print "Getting xml results for binary ID: $bin_id at $link\n";
	`wget -q -O $xml "$link" 2>/dev/null`;
        if ($? == 0) {
	 $body = `$c_xalanbin -in $xml -xsl $c_surfidsdir/include/ViewAnalysis.xslt`;
         $body =~ s/'/ /g;
         $body =~ s/\\/\\\\/g;
         $body =~ s/\n+/\n/g;
         $xml2 = `cat $xml`;
         $xml2 =~ s/'/ /g;
         $xml2 =~ s/\\/\\\\/g;
    
         open(LOG, "> $mailfile");
         print LOG "$body";
         close(LOG);
    
         # This helps remove non-UTF8 characters that make postgres unhappy
         $body2 = encode("utf8", $body);
         $logit = 1;
	} else { 
	   $logit = 0;
	}
      } else {
        $logit = 0;	
      }
    }
      
   if ($logit == 1) { 
    
    ## Get all binid that are already logged
    $sth_binid = $dbh->prepare("SELECT binid FROM cwsandbox");
    $execute_result = $sth_binid->execute();
    $hash_refcwsandbox = $sth_binid->fetchall_hashref('binid');
    
    $sth_md5 = $dbh->prepare("SELECT id FROM uniq_binaries WHERE name = '$md5'");
    $execute_result = $sth_md5->execute();
    $numrows_md5 = $sth_md5->rows;
    @bin_id = $sth_md5->fetchrow_array; 
    $bin_id = $bin_id[0];
    if ($numrows_md5 == 0) {
      $sth_putmd5 = $dbh->prepare("INSERT INTO uniq_binaries (name) VALUES ('$md5')");
      $execute_result = $sth_putmd5->execute();
      $sth_md5 = $dbh->prepare("SELECT id FROM uniq_binaries WHERE name = '$md5'");
      $execute_result = $sth_md5->execute();
      $numrows_md5 = $sth_md5->rows;
      @bin_id = $sth_md5->fetchrow_array; 
      $bin_id = $bin_id[0];
    }
    if (!exists $hash_refcwsandbox->{ $bin_id }) {
      print "Adding new CWSandbox result info for binary ID: $bin_id\n";
      $sth_putcwsandbox = $dbh->prepare("INSERT INTO cwsandbox (binid, xml, result) VALUES ('$bin_id', '$xml2', '$body2')");
      $execute_result = $sth_putcwsandbox->execute();
    } else {
      print "CWSandbox report of binary ID: $bin_id already logged\n";
    }
   }
  }
  if ("$md5" ne "") {
    ##############
    # BINARIES_DETAIL
    ##############
    # Check if the binary was already in the binaries_detail table.
    $sth_checkmd5 = $dbh->prepare("SELECT id FROM uniq_binaries WHERE name = '$md5'");
    $execute_result = $sth_checkmd5->execute();
    $numrows_checkmd5 = $sth_checkmd5->rows;
    if ($numrows_checkmd5 == 0) {
    
      # If not, we add the filesize and file info to the database. 
      # Getting the info from linux file command. 
    
      $filepath = "$c_bindir/$md5";
      if (-e "$filepath") {
        $fileinfo = `file $filepath`;
        @fileinfo = split(/:/, $fileinfo);
        $fileinfo = $fileinfo[1];
        chomp($fileinfo);

        # Getting the file size.
        $filesize = (stat($filepath))[7];
     
        print "Adding new binary_detail info for binary ID: $bin_id\n";
        $sql_checkbin = "INSERT INTO binaries_detail (bin, fileinfo, filesize) VALUES ($bin_id, '$fileinfo', $filesize)";
        $sth_checkbin = $dbh->prepare($sql_checkbin);
        $result_checkbin = $sth_checkbin->execute();
      } else { print "File does not exists\n"; }
    }
    $md5 = "";
  }
}

# close connection
$pop->Close();

# Lets be nice and clean up our stuff
my $word = "msg";
my $word2 = "analysis";
my $word3 = "mail";
my $word4 = "xml";

opendir (DIR,$c_cwmime);
@files = grep(/$word/, readdir (DIR));
closedir (DIR);
foreach $file (@files) {
  unlink "$c_cwmime/$file";
}

opendir (DIR,$c_cwmime);
@files2 = grep(/$word2/, readdir (DIR));
closedir (DIR);
foreach $file2 (@files2) {
  unlink "$c_cwmime/$file2";
}

opendir (DIR,$c_cwtemp);
@files3 = grep(/$word3/, readdir (DIR));
closedir (DIR);
foreach $file3 (@files3) {
  unlink "$c_cwtemp/$file3";
}

opendir (DIR,$c_cwtemp);
@files4 = grep(/$word4/, readdir (DIR));
closedir (DIR);
foreach $file4 (@files4) {
  unlink "$c_cwtemp/$file4";
}

if (-e $c_cwmime) {
  rmdir($c_cwmime) || warn "Cannot rmdir mimetemp: $!";
}
exit;

sub dump_entity {
  my ($entity, $name) = @_;
  defined($name) or $name = "'anonymous'";
  my $IO;

  # Output the body:
  my @parts = $entity->parts;
  if (@parts) {
    # multipart...

    my $i;
    foreach $i (0 .. $#parts) {       # dump each part...
      dump_entity($parts[$i], ("$name, part ".(1+$i)));
    }
  } else { 
    # single part...

    # Get MIME type, and display accordingly...
    my ($type, $subtype) = split('/', $entity->head->mime_type);
    my $body = $entity->bodyhandle;
    if ($type =~ /^application$/) {
      if ($IO = $body->open("r")) {
        open(LOG, "> $xml");
        print LOG "$_" while (defined($_ = $IO->getline));
        close(LOG);
        $IO->close;
      } else {
        # d'oh!
        print "$0: couldn't find/open '$name': $!";
      }
    }
  }
}

sub mimeextract {
  # Create a new MIME parser:
  my $parser = new MIME::Parser;
    
  # Create and set the output directory:
  (-d "$c_cwmime") or mkdir "$c_cwmime",0755 or die "mkdir: $!";
  (-w "$c_cwmime") or die "can't write to directory";
  $parser->output_dir("$c_cwmime");
    
  # Read the MIME message:
  $entity = $parser->parse_data(@_) or die "couldn't parse MIME stream";

  # Dump it out:
  dump_entity($entity);
}
