use strictures 1;
use Test::More;
use Web::Stat;
use Data::Dumper::Concise;
use 5.010;

my $webstat = Web::Stat->new;
$webstat->read_log_tail;
my $count = $webstat->line_count;
say "Line count: $count";
say "first request: ", $webstat->first_good_request;
say "last request: ", $webstat->last_good_request;
say Dumper $webstat->unique_request_counts_by_IP;

ok(1);

done_testing();