Tak
===

An Erlang library to perform SSL certificate pinning.

<object width="450" height="508"><param name="movie" value="http://backend.deviantart.com/embed/view.swf?1"><param name="flashvars" value="id=206804610&width=1337"><param name="allowScriptAccess" value="always"><embed src="http://backend.deviantart.com/embed/view.swf?1" type="application/x-shockwave-flash" width="450" height="508" flashvars="id=206804610&width=1337" allowscriptaccess="always"></embed></object><br><a href="http://invaderjabber.deviantart.com/art/Tak-206804610">Tak</a> by <span class="username-with-symbol u"><span class="simple-symbol">~</span><a class="u regular username" href="http://invaderjabber.deviantart.com/" >InvaderJabber</a><span class="user-symbol regular " data-quicktip-text="" data-show-tooltip=""></span></span> on <a href="http://www.deviantart.com">deviantART</a>

Validating the SSL certificate presented by a server can be a very challenging task. There are an inordinately large number of complicated rules to follow, and one change in DNS or leaving the certificate alone for more than a year can result in validation failures - the names don't match or the certificate expires. Additionally, if we validate certificates in the same manner that web browsers do, we'll trust anyone's certificate for 'secureservice.example.com' no matter if we know that it should only ever be signed by "Bob's CA and Grill".

We can skip most of the complication if we give the SSL client a copy of the only certificates that should be used by the server - this approach is known as Certificate Pinning.

Tak is a library that helps you process certificate chains and turn them into a configuration usable with the SSL client library in Erlang/OTP.

Build
-----

    $ rebar compile

Pinning a connection to a certificate
-------------------------------------

To start with, your application will need a copy of the SSL certificate chain used by the server you want to connect to. This chain should be in PEM form (the one that looks like "-----BEGIN CERTIFICATE-----").

At application start time, you should read this pem data and run it through `tak:pem_to_cert_chain/1`. For instance, if the certificate chain lives in the file `myapp/priv/service_certs.pem`, you could do something like:

    FileName = filename:join(code:priv_dir(?MODULE),
                             "service_certs.pem"),
    {ok, PemData} = file:read_file(FileName),
    ServiceCertChain = tak:pem_to_cert_chain(PemData).

You can even pre-prepare the options you'll need to pass to the `ssl` library:

    ServiceSSLOptions = tak:chain_to_ssl_options(ServiceCertChain).


Then when you want to connect to the service:

    ssl:connect("service.example.com", 443, ServiceSSLOptions).

This will then connect to the service and validate that the certificate the server presents is exactly the same as our copy.

Advice
------

Turning the PEM data into the certificate chain and then the SSL options is a somewhat expensive process. Why not do that once at startup and then store it in the application environment for your OTP app?

    application:set_env(my_cool_app, service_ssl_options,
                        tak:chain_to_ssl_options(tak:pem_to_cert_chain(PemData))).

Then when you need to use it, just:

    ssl:connect("service.example.com", 443,
                application:get_env(my_cool_app, service_ssl_options)).

This makes sure the processing happens once and is stored in ETS for quick use at connect time.