use strictures 1;
package Web::Stat;
use 5.010;
use Moo;
use IPC::System::Simple qw/ system /;

has log_file => ( is => 'ro', default => sub { '/var/log/apache2/access.log' }, );
has tail_size                   => (is => 'rw', default => sub {2000}, );
has total_requests              => (is => 'rw');
has line_count                  => (is => 'rw', default => sub {0}, );
has first_request               => (is => 'rw', default => sub {0}, );
has first_good_request          => (is => 'rw', );
has last_good_request           => (is => 'rw', );
has last_request                => (is => 'rw');
has last_40_requests            => (is => 'rw');
has total_bytes                 => (is => 'rw');
has total_errors                => (is => 'rw');
has total_good                  => (is => 'rw');
has unique_request_counts_by_IP => (is => 'rw');

sub read_log_tail {
    my ($self) = @_;
    my $request_filter;

## Grab search_month
    my %month_map = (
        "Jan", 1, "Feb", 2, "Mar", 3, "Apr", 4,  "May", 5,  "Jun", 6,
        "Jul", 7, "Aug", 8, "Sep", 9, "Oct", 10, "Nov", 11, "Dec", 12
    );

## Initial values ##
    my $num_of_testlines = 0;
    my $corrupt_requests = 0;
    my $status_errors    = 0;
    my $tot_apps         = 0;
    my $tot_robots       = 0;

    my $log_format = "Extended";
    my $delimiter  = " ";

    my $IP         = "0";
    my $Server     = "1";
    my $User       = "2";
    my $Date_Time  = "3";
    my $Offset     = "4";
    my $Method     = "5";
    my $URL        = "6";
    my $Protocol   = "7";
    my $Status     = "8";
    my $Bytes      = "9";
    my $Referer    = "10";
    my @User_Agent = "11";

    my (
        $line_count,    @req,                $filtered_requests,
        $first_request, $first_good_request, $vector_size,
        $total_bytes,   $good_requests,      $status,
        %status_errors, $tot_nogif_nojpg_noxbm
    );
## initialize last 40 hits array
    my $array_size = 0;
    my @array_40;

    # Get the log tail from the unix process 'tail'
    my $logfile   = $self->log_file;
    my $tail_size = $self->tail_size;
    delete $ENV{'PATH'};
    my $tmp_file = '/tmp/tail.log';
    system("/usr/bin/tail -$tail_size $logfile > $tmp_file");
    open( L, "$tmp_file" ) or die "Can't open tmp file: $tmp_file\n";
## Cycle through the hits of the tail
  HIT:
    my ( %u_all, %unique, $last_good_request );
    while (<L>) {
        #   print "$_<br>";
        $self->line_count($self->line_count + 1);
        @req = split( /$delimiter/, $_ );

        ## crop long query strings off at 64 char
        if ( $req[$URL] =~ m/\?.*\&/ ) {
            if ( length $req[$URL] ) {
                $req[$URL] = substr( $req[$URL], 0, 72 );
                $req[$URL] =~ s/^(.*)\W(.*)$/$1/;
            }

            #print $req[$URL]."<br>\n";
        }

        my @filter_ips = ( '72.174.62.35', '66.249.72.176' );
        ## Deal with filtered domain
        foreach my $ip (@filter_ips) {
            if ( $req[$IP] =~ /$ip/ ) {
                $filtered_requests++;
                next HIT;
            }
        }

        $vector_size = @req;

## Store first good request.
        if ( $self->first_request != 1 ) {
            $self->first_good_request($_);
            $self->first_request(1);
        }

        # Obtain bytes transferred
        unless ( $req[$Bytes] eq '-' ) {

            #print "bytes: $req[$Bytes]<br />\n";
            $total_bytes += $req[$Bytes];

            #print "$total_bytes<br />";
        }

        # Looking for status codes 4xx and 5xx
        # which represent server and client errors.
        $status = $req[$Status];

        if ( $req[$Status] =~ /^[45]/ ) {
            $status_errors++;
            $status_errors{$status}++;
            next;
        }

        # Counting the Content-Types

        $good_requests++;

        # Filter out certain request types
        # since (currently) we're most interested
        # in page impressions and MojoMojo has a lot
        # of requests 'superfluous' to page counts.
        my $filtered_request_counts;
        given ( $req[$URL] ) {
            foreach my $type ( keys %{$request_filter} ) {
                my $regex = $request_filter->{$type};
                when (/$regex/i) {
                    $filtered_request_counts->{$type}++;
                    next HIT;

                    #warn "URL $_";
                }
            }
        }
        $tot_nogif_nojpg_noxbm++;

        # Build last 40 hits array.
        if ( $array_size < 40 ) {
            unshift @array_40, $_;
            $array_size++;
        }
        else {
            unshift @array_40, $_;
            pop @array_40;
        }

        #      if($req[$URL] =~ /robots.txt/i) {
        #         print "found a robot<br>\n";
        #         $tot_robots++;
        #         next;
        #      }

        if ( $req[$URL] =~ /\.cgi/i || /\.pl/i || /\.class/i || /\.exe/i ) {
            $tot_apps++;
        }

        my $ip   = $req[$IP];
        my $html = $req[$URL];

        #  print $ip;

        my @html = split( /\//, $html );
        $html = pop(@html)||'';
        my $tmp = pop(@html)||'';
        $html = "$tmp/$html";
        unless ($html) {
            $html = pop(@html);
        }
        $unique{$html}{$ip}++;
        $u_all{$ip}++;
        $self->last_good_request($_);

    }    ######### End of while that reads in log file ##########
    
    $self->unique_request_counts_by_IP(\%unique);
}

1;
