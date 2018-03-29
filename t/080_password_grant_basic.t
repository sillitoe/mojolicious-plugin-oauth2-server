#!perl

use strict;
use warnings;

use Mojolicious::Lite;
use Test::More;
use FindBin qw/ $Bin /;
use lib $Bin;
use AllTests;

MOJO_APP: {
  # plugin configuration
  plugin 'OAuth2::Server' => {
  jwt_secret => 'foo',
    clients              => {
      1 => {
        client_secret => 'boo',
        scopes        => {
          eat       => 1,
          drink     => 0,
          sleep     => 1,
        },
      },
    },
    users => {
      bob => 'hey_ho!',
    }
  };

  group {
    # /api - must be authorized
    under '/api' => sub {
      my ( $c ) = @_;
      return 1 if $c->oauth;
      $c->render( status => 401, text => 'Unauthorized' );
      return undef;
    };

    get '/eat' => sub { shift->render( text => "food"); };
  };

  # /sleep - must be authorized and have sleep scope
  get '/api/sleep' => sub {
    my ( $c ) = @_;

    if ( my $auth_details = $c->oauth( 'sleep' ) ) {
      die "Time to die... (or is it?)";
      $c->render( text => "Time for bed, " . ucfirst( $auth_details->{user_id} ) );
    } else {
      $c->render( status => 401, text => 'You cannot sleep' );
    }
  };
};

AllTests::run({
  grant_type        => 'password',
  skip_revoke_tests => 1, # there is no auth code
});

done_testing();

# vim: ts=2:sw=2:et
