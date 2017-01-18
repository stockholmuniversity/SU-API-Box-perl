package SU::API::Box;

use strict;
use warnings;

use Crypt::JWT qw(encode_jwt);
use HTTP::Request;
use JSON;
use LWP::UserAgent;
use String::Random;
use URI::Escape;

sub new {
    my $class = shift;
    my $self = {
        client_id => shift,
        client_secret => shift,
        sub => shift,
        box_sub_type => shift,
    };

    $self->{url} = "https://api.box.com/oauth2";

    $self->{ua} = LWP::UserAgent->new;
    $self->{ua}->default_header('Accept' => 'application/json');
    $self->{login_status} = "not logged in";

    bless $self, $class;
    return $self;
};

sub do_request {
    my ($self,$method,$uri,$params,$data) = @_;

    my $request_url;
    $request_url = "$self->{url}/${uri}";

    my $req;

    if ($uri =~ /^token$/ && $params) {
        $req = HTTP::Request->new($method => $request_url);
        $req->content_type("application/x-www-form-urlencoded");
        $data = $params;
        $req->content($data);
    } else {
        if ($params) {
            $params = encode_params($params);
            $request_url = "$self->{url}/${uri}?$params";
        };
        $req = HTTP::Request->new($method => $request_url);

        if ($data) {
            $data = encode_json($data);
            $req->content($data);
         };
    };
    $self->{res} = $self->{ua}->request($req);

    if (!$self->{res}->is_success) {
        return undef;
    };
    my $json_result = decode_json($self->{res}->content);

    if ($json_result) {
        return $json_result;
    };
    return undef;
};

sub encode_params {
    my $filter = $_[0];
    my @filter_array;
    my @encoded_uri_array;

    if($filter =~ /&/) {
        @filter_array = split('&',$filter);
    } else {
        @filter_array = $filter;
    };
    for(@filter_array) {
        if($_ =~ /=/) {
            my ($argument,$value) = split("=",$_);
            push(@encoded_uri_array,join("=",uri_escape($argument),uri_escape($value)));
        } else {
            push(@encoded_uri_array,uri_escape($_));
        };
    };
    return join("&",@encoded_uri_array);
};

sub login {
    my ($self,$key_file,$kid) = @_;

    $self->{key_file} = $key_file;
    $self->{kid} = $kid;
    if ( ! -f $key_file) {
        $self->{login_status} = "Can't locate key file: $key_file";
        return undef;
    } else {
        open(my $fh, '<', $key_file) or die "cannot open file $key_file";
        {
            local $/;
            $self->{key} = <$fh>;
        };
        close($fh);

        my $random = new String::Random;
        my $time = time + 60;
        my $jti = $random->randpattern("...................................");
        my %post_data = (
                 "iss" => "$self->{client_id}",
                 "sub" => "$self->{sub}",
                 "box_sub_type" => "$self->{box_sub_type}",
                 "aud" => "https://api.box.com/oauth2/token",
                 "jti" => "$jti",
                 "exp" => $time);

        my $json_post_data = encode_json \%post_data;
        my $jws = encode_jwt(payload => $json_post_data,
                             alg => 'RS256',
                             key => \$self->{key},
                             extra_headers => { kid => $kid,
                                                typ => "JWT"
                                              }
                            );

        my $params = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&client_id=$self->{client_id}&client_secret=$self->{client_secret}&assertion=$jws";
        my $response = $self->do_request("POST", "token", "$params", "");


        if ($self->request_code == 200) {
            $self->{login_status} = "login successful";
            $self->{access_token} = $response->{access_token};
        } else {
            $self->{login_status} = "unknown status line: " . $self->{res}->status_line;
        };
    };

    $self->{ua}->default_header('Accept' => 'application/json',
                                'Authorization' => "Bearer $self->{access_token}");
    $self->{url} = "https://api.box.com/2.0";
    return $self->{access_token};
};

sub logout {
    my ($self) = @_;
    $self->{access_token} = undef;
};

sub request_code {
    my ($self) = @_;
    return $self->{res}->code;
};

sub request_status_line {
    my ($self) = @_;
    return $self->{res}->status_line;
};

sub logged_in {
    my ($self) = @_;
    return $self->{access_token};
};

sub login_status {
    my ($self) = @_;
    return $self->{login_status};
};

sub DESTROY {
    my ($self) = @_;
    if ($self->{ua} && $self->{access_token}) {
        $self->logout();
    } elsif ($self->{access_token}) {
        warn "Automatic logout failed";
    };
};

1;
