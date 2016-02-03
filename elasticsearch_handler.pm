#!/usr/bin/perl

package elasticsearch_handler;
use strict;
use warnings;

use nginx;
use JSON;
use LWP;

my @url_whitelist = qw ( \.kibana );
my $url_whitelist = join ( "|", @url_whitelist ); 
   $url_whitelist = qr/$url_whitelist; 
   
my @rewrite = qw ( _msearch );
my $rewrite = join ( "|", @rewrite );
   $rewrite = qr/$rewrite/;

my @cond_reject = qw ( _mget );
my $cond_reject = join ( "|", @cond_reject ); 
   $cond_reject = qr/$cond_reject/; 
   
my %allow_group = ( "user1" => [ "groupa", "groupb" ],
                    "default" => [ 'NO_GROUP' ] );
                    
foreach my $user ( keys %allow_group ) { 
    my $regex = join ( "|", map { quotemeta } @{$allow_group{$user}} );
    $regex = qr/$regex/; 
    $allow_get{$user} = "logstash-".$regex;
}
my $allow_get_all = qr/^\.kibana/; 

sub handle_es_request { 
   my ($request) = @_;
   if ( $request -> uri =~ m/$url_whitelist/ ) { 
       $request -> internal_redirect('/es'.$request->variable('request_uri'));
       return OK;
    }
    $request -> has_request_body ( \&rewrite_request_body ); 
    $request -> internal_redirect ( '/es'.$request->variable('request_uri'));
    return OK;
}

sub rewrite_request_body { 
    my ( $request ) = @_; 
    my $post_data = $request -> request_body // do { local $/; open ( my $input, '<', $request -> request_body_file ) ; <$input> };
    if ( $request -> uri =~ m/$conditional_reject/ ) {
       my $dn = $request -> header_in ( 'X-client-s-dn' ) // "default"; 
    
    my @chunks = split ( "\n", @post_data ); 
    foreach my $chunk ( @chunks ) { 
      if ( my $json_obj = eval { decode_json($chunk) } ) { 
        if ( defined $json_obj -> {docs} ) { 
          foreach my $doc ( @{$json_obj->{docs}} ) { 
             if ( $doc -> {_index} 
             and not $doc -> {_index} =~ m/$allow_get{$dn}/
             and not $doc -> {_index} =~ m/$allow_get_all/ ) { 
                 return HTTP_FORBIDDEN;
            }
          }
          return 1; #pass through
        }
      }
    }
    
    if ( $request -> uri =~ m/$rewrite_uri/ ) { 
       my $dn = $request -> header_in('X-client-s-dn' ) // "default";
       
       my @chunks = split ( "\n", $post_data );
       foreach my $chunk ( @chunks ) { 
          if ( my $json_obj = eval { decode_json($chunk) } ) {
            if ( $json_obj -> {query} ) {
              foreach my $group ( @{$allow_group{$dn}} ) {
                 push ( @{ $json_obj -> {query} -> {filtered} -> {filter} -> {bool} -> {should} }, 
                     { query => { match => { server_group => { query => $group, type => "phrase" }}}});
              }
              $chunk = encode_json($json_obj)."\n";
            }
          }
        }
        my $new_post_data = join ( "\n", @chunks ); 
        my $agent = LWP::UserAgent -> new;
        my $new_request = HTTP::Request -> new ( POST => 'http://localhost:6060/es'.$request->variable('request_uri') );
        $new_request -> content ( $new_post_data ); 
        my $response = $agent -> request ( $new_request ); 
        $request -> discard_request_body;
        $request -> send_http_header ( $response -> content_type ); 
        $request -> print ( $response -> content ); 
        return $response -> code;
      }
      return 1;
  }
  
  1;
}
