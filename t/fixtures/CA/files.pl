use File::Slurp qw(read_file);

[
    [ "server.crt" => CORE::join('',
        read_file('t/fixtures/CA/server.crt'),
    ) ],
    [ "server-bundle.crt" => CORE::join('',
        read_file('t/fixtures/CA/server.crt'),
        read_file('t/fixtures/CA/intermediate-ca.crt'),
        read_file('t/fixtures/CA/root-ca.crt'),
    ) ],
    [ "ca.crt" => CORE::join('',
        read_file('t/fixtures/CA/intermediate-ca.crt'),
        read_file('t/fixtures/CA/root-ca.crt'),
    ) ],
    [ "server.key" => CORE::join('', read_file('t/fixtures/CA/server.key')) ],
    [ "client.crt" => CORE::join('',read_file('t/fixtures/CA/client.crt')) ],
    [ "client-bundle.crt" => CORE::join('',
        read_file('t/fixtures/CA/client.crt'),
        read_file('t/fixtures/CA/intermediate-ca.crt'),
        read_file('t/fixtures/CA/root-ca.crt'),
    ) ],
    [ "client.key" => CORE::join('', read_file('t/fixtures/CA/client.key')) ],
]
