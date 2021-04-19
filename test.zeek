@load base/frameworks/sumstats
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="404_response", $apply=set(SumStats::UNIQUE));
    local r2 = SumStats::Reducer($stream="response", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="http_scan",
                      $epoch=10mins,
                      $reducers=set(r1,r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local ru1 = result["404_response"];
                        local ru2 = result["response"];
                        if (ru1$num > 2){
					      if (ru1$num / ru2$num > 0.2){
						    if (ru1$unique / ru1$num > 0.5){
							print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, ru1$num, ru1$unique);
					        }
					      }
					    }
                        }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    SumStats::observe("response", [$host = c$id$orig_h], [$str = c$http$uri]);
	if (code == 404){
		SumStats::observe("404_response", [$host = c$id$orig_h], [$str = c$http$uri]);
    }
    }
