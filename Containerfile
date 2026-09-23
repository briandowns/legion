FROM ghcr.io/freebsd/freebsd-toolchain:15.1 AS build

ENV ASSUME_ALWAYS_YES=yes
RUN pkg update && \
    pkg install -y \
        FreeBSD-clang \
        llvm \
        libmicrohttpd \
        jansson \
        libwebsockets \
        libuuid \
        curl \
        git \
        gmake \
        gnutls \
        openssl \
        sqlite3

WORKDIR /app
COPY . .

RUN git clone --depth 1 https://github.com/briandowns/libspinner && \
    cd libspinner && \
    gmake && \
    gmake install

RUN git clone --depth 1 https://github.com/briandowns/librattler && \
    cd librattler && \
    gmake && \
    gmake install

RUN git clone --depth 1 https://github.com/briandowns/liblogger && \
    cd liblogger && \
    gmake && \
    gmake install

RUN git clone --depth 1 https://github.com/briandowns/libmaple && \
    cd libmaple && \
    gmake && \
    gmake install

RUN git clone --depth 1 https://github.com/briandowns/libpapago && \
    cd libpapago && \
    gmake PAPAGO_USE_MAPLE=1 PAPAGO_WITH_WSC=1 && \
    gmake install PAPAGO_USE_MAPLE=1 PAPAGO_WITH_WSC=1

RUN gmake

FROM ghcr.io/freebsd/freebsd-notoolchain:15.1

ENV ASSUME_ALWAYS_YES=yes
RUN pkg update && \
    pkg install -y \
        libmicrohttpd \
        jansson \
        libwebsockets \
        openssl \
        gnutls

COPY --from=build /usr/local/include/maple.h /usr/local/include/
COPY --from=build /usr/local/lib/libmaple.so /usr/local/lib/
COPY --from=build /usr/local/include/spinner.h /usr/local/include/
COPY --from=build /usr/local/lib/libspinner.so /usr/local/lib/
COPY --from=build /usr/local/include/logger.h /usr/local/include/
COPY --from=build /usr/local/lib/liblogger.so /usr/local/lib/
COPY --from=build /usr/local/include/papago_wsc.h /usr/local/include/
COPY --from=build /usr/local/include/papago.h /usr/local/include/
COPY --from=build /usr/local/lib/libpapago.so /usr/local/lib/
COPY --from=build /usr/local/include/rattler.h /usr/local/include/
COPY --from=build /usr/local/lib/librattler.so /usr/local/lib/
COPY --from=build /app/bin/legion /usr/local/bin

ENTRYPOINT["legion"]

