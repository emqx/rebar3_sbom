-module(rebar3_sbom_cyclonedx_json).

-export([bom/3, merge/1]).

-define(APP, <<"rebar3_sbom">>).
-define(DEFAULT_VERSION, <<"1">>).

bom(File, Components, Opts) ->
    ValidComponents = lists:filter(fun(E) -> E =/= undefined end, Components),
    Serial = rebar3_sbom_cyclonedx:uuid(),
    Content = #{
        bomFormat => <<"CycloneDX">>,
        specVersion => <<"1.4">>,
        serialNumber => bin(Serial),
        version => ?DEFAULT_VERSION,
        metadata => metadata(),
        components => [component(Component) || Component <- ValidComponents],
        dependencies => [dependency(Component) || Component <- ValidComponents]
    },
    Bom = update_version(File, Content, Opts),
    jsone:encode(Bom, [{indent, 4}, {space, 1}, native_forward_slash]).

merge(Args) ->
    Files = [Value || {Key, Value} <- Args, Key =:= merge],
    Jsons = [
        begin
            {ok, Json} = load_json(File),
            Json
        end
     || File <- Files
    ],
    jsone:encode(do_merge(Jsons), [{indent, 4}, {space, 1}, native_forward_slash]).

metadata() ->
    #{
        timestamp => bin(calendar:system_time_to_rfc3339(erlang:system_time(second))),
        tools => [#{name => ?APP}]
    }.

component(Component) ->
    lists:foldl(
        fun
            ({_, undefined}, Acc) ->
                Acc;
            ({_, []}, Acc) ->
                Acc;
            ({Field, Value}, Acc) ->
                component_field(Field, Value, Acc)
        end,
        #{
            type => <<"library">>,
            'bom-ref' => bom_ref_of_component(Component)
        },
        Component
    ).

component_field(name, Name, Acc) ->
    Acc#{name => bin(Name)};
component_field(version, Version, Acc) ->
    Acc#{version => bin(Version)};
component_field(author, Author, Acc) ->
    Acc#{author => bin(string:join(Author, ","))};
component_field(description, Description, Acc) ->
    Acc#{description => bin(Description)};
component_field(licenses, Licenses, Acc) ->
    Acc#{licenses => [license(License) || License <- Licenses]};
component_field(purl, Purl, Acc) ->
    Acc#{purl => bin(Purl)};
component_field(sha256, Sha256, Acc) ->
    Acc#{hashes => [#{alg => <<"SHA-256">>, content => bin(Sha256)}]};
component_field(_, _, Acc) ->
    Acc.

license(Name) ->
    case rebar3_sbom_license:spdx_id(Name) of
        undefined ->
            #{name => bin(Name)};
        SpdxId ->
            #{id => bin(SpdxId)}
    end.

update_version(File, Bom, Opts) ->
    Bom#{version => get_version(File, Bom, Opts)}.

get_version(File, Bom, Opts) ->
    case load_json(File) of
        {ok, #{version := Value} = Old} ->
            case is_strict_version(Opts) andalso is_bom_equal(Old, Bom) of
                true ->
                    Value;
                _ ->
                    Version = erlang:binary_to_integer(Value),
                    erlang:integer_to_binary(Version + 1)
            end;
        {error, enoent} ->
            ?DEFAULT_VERSION;
        {error, Reason} ->
            logger:error(
                "scan file:~ts failed, reason:~p, will use the default version number 1",
                [File, Reason]
            ),
            ?DEFAULT_VERSION
    end.

is_strict_version(Opts) ->
    proplists:get_value(strict_version, Opts, true).

is_bom_equal(#{components := CA, dependencies := DA}, #{components := CB, dependencies := DB}) ->
    CA =:= CB andalso DA =:= DB;
is_bom_equal(_, _) ->
    false.

dependency(Component) ->
    Ref = bom_ref_of_component(Component),
    Deps = proplists:get_value(dependencies, Component, []),
    #{
        ref => Ref,
        dependsOn => [bom_ref_of_component([{name, Dep}]) || Dep <- Deps]
    }.

bom_ref_of_component(Component) ->
    Name = proplists:get_value(name, Component),
    bin(lists:flatten(io_lib:format("ref_component_~ts", [Name]))).

bin(Str) when is_list(Str) ->
    unicode:characters_to_binary(Str);
bin(Bin) ->
    Bin.

load_json(File) ->
    case file:read_file(File) of
        {ok, Bin} ->
            case jsone:try_decode(Bin, [{keys, atom}]) of
                {ok, Json, _} ->
                    {ok, Json};
                {error, {Reason, _Stack}} = Error ->
                    logger:error(
                        "parse file:~ts failed, reason:~p, will use the default version number 1",
                        [File, Reason]
                    ),
                    Error
            end;
        {error, Reason} = Error ->
            logger:error(
                "scan file:~ts failed, reason:~p, will use the default version number 1",
                [File, Reason]
            ),
            Error
    end.

do_merge([Init | _] = Jsons) ->
    do_merge(Jsons, Init, make_cache([], #{}), make_cache([], #{})).

do_merge([#{components := Comps, dependencies := Deps} | T], Init, CompCache, DepsCache) ->
    do_merge(
        T,
        Init,
        merge_list_by_name(name, CompCache, Comps),
        merge_list_by_name(ref, DepsCache, Deps)
    );
do_merge([], Init, CompCache, DepsCache) ->
    Init#{
        components := CompCache(undefined, undefined),
        dependencies := DepsCache(undefined, undefined)
    }.

merge_list_by_name(Name, Cache, List) ->
    lists:foldl(
        fun(E, Acc) ->
            Acc(Name, E)
        end,
        Cache,
        List
    ).

make_cache(Result, Cache) ->
    fun
        (undefined, undefined) ->
            lists:reverse(Result);
        (Name, Obj) ->
            Key = maps:get(Name, Obj),
            case maps:is_key(Key, Cache) of
                false ->
                    make_cache([Obj | Result], Cache#{Key => true});
                true ->
                    make_cache(Result, Cache)
            end
    end.
