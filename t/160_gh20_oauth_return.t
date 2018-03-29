#!perl

use strict;
use warnings;

package OAuthCheckReturn;

use Mojo::Base qw( Mojolicious );
use Data::Dumper;

my %auth_config = (
  clients => {
    'contributor' => {
      client_secret => 'clientclientclientclientclientclient',
      scopes => {
        'can_write' => 1,
      },
    },
  },
  users => {
    test_user   => 'test_password',
  },
  jwt_secret    => 'jwtjwtjwtjwtjwtjwtjwtjwtjwtjwtjwtjwtjwt',
);

sub startup {
  my $self = shift;

  # Router
  my $r = $self->routes;

  # Auth
  my $private = $r->under('/private' => sub {
     my $c = shift;

     my $log  = $c->app->log;
     my $tx   = $c->tx;
     my $ip   = $c->tx->remote_address;
     my $path = $c->req->url->path;

     $log->debug( "REQUEST.URL:      " . $tx->req->url );
     $log->debug( "REQUEST.PARAMS:   " . $tx->req->params->to_string );
     $log->debug( "REQUEST.BODY:     " . $tx->req->body );
     $log->debug( "REQUEST.HEADERS:  " . $tx->req->headers->to_string );
     $log->debug( "REQUEST.IP:       " . $ip );

     if ( my $oauth_details = $c->oauth ) {
	     $log->info( "OAUTH: " . Dumper( $oauth_details ) );
       $log->info( sprintf "Authenticated: %s ip=%s client=%s user=%s scope=%s",
         $path, $ip, $oauth_details->{client}, $oauth_details->{user_id}, join( ",", @{$oauth_details->{scopes} || []} )
			 );
       return 1;
     }
     else {
       # not authenticated
       $log->info( sprintf "NOT Authenticated: %s ip=%s", $path, $ip );
       $c->render( status => 401, json => { message => "Sorry, the API endpoint '$path' requires authorization" } );
     }

     return;
   }
  );

  $private->get('authenticated_as' => sub {
    my $c = shift;
    if ( my $oauth_details = $c->oauth ) {
      $c->render( json => { message => "Yay!", username => $oauth_details->{username} } );
    }
    else {
      $c->render( json => { message => "Boo!" } );
    }
    return;
  });

  $self->plugin("OAuth2::Server" => \%auth_config );
}

package main;

use strict;
use warnings;

use Test::Mojo;
use Test::More;
use Mojolicious::Commands;

my $t = Test::Mojo->new( 'OAuthCheckReturn' );

my %token_params = (
  client_id => 'contributor',
  client_secret => 'clientclientclientclientclientclient',
  grant_type => 'password',
  scope => ['can_write'],
);

# not authorized
$t->get_ok('/private/authenticated_as')
   ->status_is( 401 )
   ->json_is( { message => 'Boo!' } );

my %params = ( %token_params, username => 'test_user', password => 'test_password' );

# get auth token
$t->post_ok('/oauth/access_token', form => \%params)
  ->status_is( 200 );
my $access_token = $t->tx->res->json->{access_token} // '';

# set auth token
$t->ua->on(start => sub {
  my ($ua, $tx) = @_;
  $tx->req->headers->header( 'Authorization' => "Bearer $access_token" );
});

# auth should work
# [Thu Mar 29 18:52:01 2018] [error] Can't use string ("contributor") as a HASH ref while "strict refs" in use at t/160_gh20_oauth_return.t line 50.
$t->get_ok('/private/authenticated_as')
  ->status_is( 200 )
  ->json_is( { message => 'Yay!', username => 'test_user' } );

done_testing();
