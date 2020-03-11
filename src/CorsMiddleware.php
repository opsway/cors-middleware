<?php

/*

Copyright (c) 2016-2019 Mika Tuupola

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

/**
 * @see       https://github.com/tuupola/cors-middleware
 * @see       https://github.com/neomerx/cors-psr7
 * @see       https://www.w3.org/TR/cors/
 * @license   https://www.opensource.org/licenses/mit-license.php
 */

declare(strict_types=1);

namespace Tuupola\Middleware;

use Closure;
use Neomerx\Cors\Analyzer as CorsAnalyzer;
use Neomerx\Cors\Contracts\AnalysisResultInterface as CorsAnalysisResultInterface;
use Neomerx\Cors\Contracts\Constants\CorsResponseHeaders;
use Neomerx\Cors\Strategies\Settings as CorsSettings;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Tuupola\Http\Factory\ResponseFactory;
use Tuupola\Middleware\DoublePassTrait;

use function parse_url;

final class CorsMiddleware implements MiddlewareInterface
{
    const ALLOW_ALL_ORIGIN = "*";

    use DoublePassTrait;

    private $logger;
    private $options = [
        "origin" => self::ALLOW_ALL_ORIGIN,
        "methods" => ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "headers.allow" => [],
        "headers.expose" => [],
        "credentials" => false,
        "origin.servers" => null,
        "cache" => 0,
        "error" => null,
        "enable.check.host" => false,
        "enable.add.allow.methods.preflight.response" => false,
        "enable.add.allow.headers.preflight.response" => false,
    ];

    public function __construct($options = [])
    {
        /* Store passed in options overwriting any defaults. */
        $this->hydrate($options);
    }

    /**
     * Execute as PSR-15 middleware.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = (new ResponseFactory())->createResponse();

        $analyzer = CorsAnalyzer::instance($this->buildSettings($request, $response));
        if ($this->logger) {
            $analyzer->setLogger($this->logger);
        }
        $cors = $analyzer->analyze($request);

        switch ($cors->getRequestType()) {
            case CorsAnalysisResultInterface::ERR_ORIGIN_NOT_ALLOWED:
                $response = $response->withStatus(401);
                return $this->processError($request, $response, [
                    "message" => "CORS request origin is not allowed.",
                ]);
            case CorsAnalysisResultInterface::ERR_METHOD_NOT_SUPPORTED:
                $response = $response->withStatus(401);
                return $this->processError($request, $response, [
                    "message" => "CORS requested method is not supported.",
                ]);
            case CorsAnalysisResultInterface::ERR_HEADERS_NOT_SUPPORTED:
                $response = $response->withStatus(401);
                return $this->processError($request, $response, [
                    "message" => "CORS requested header is not allowed.",
                ]);
            case CorsAnalysisResultInterface::TYPE_PRE_FLIGHT_REQUEST:
                $cors_headers = $cors->getResponseHeaders();
                foreach ($cors_headers as $header => $value) {
                    /* Diactoros errors on integer values. */
                    if (false === is_array($value)) {
                        $value = (string)$value;
                    }
                    $response = $response->withHeader($header, $value);
                }
                return $response->withStatus(200);
            case CorsAnalysisResultInterface::TYPE_REQUEST_OUT_OF_CORS_SCOPE:
                return $handler->handle($request);
            default:
                /* Actual CORS request. */
                $response = $handler->handle($request);
                $cors_headers = $cors->getResponseHeaders();

                foreach ($cors_headers as $header => $value) {
                    /* Diactoros errors on integer values. */
                    if (false === is_array($value)) {
                        $value = (string)$value;
                    }
                    $response = $response->withHeader($header, $value);
                }
                return $response;
        }
    }

    /**
     * Hydrate all options from the given array.
     */
    private function hydrate(array $data = []): void
    {
        foreach ($data as $key => $value) {
            /* https://github.com/facebook/hhvm/issues/6368 */
            $key = str_replace(".", " ", $key);
            $method = lcfirst(ucwords($key));
            $method = str_replace(" ", "", $method);
            $callable = [$this, $method];

            if (is_callable($callable)) {
                /* Try to use setter */
                call_user_func($callable, $value);
            } else {
                /* Or fallback to setting option directly */
                $this->options[$key] = $value;
            }
        }
    }

    /**
     * Build a CORS settings object.
     */
    private function buildSettings(ServerRequestInterface $request, ResponseInterface $response): CorsSettings
    {
        $settings = new CorsSettings();

        $this->setOriginSettings($settings);

        if (is_callable($this->options["methods"])) {
            $methods = (array) $this->options["methods"]($request, $response);
        } else {
            $methods = $this->options["methods"];
        }
        $settings->setAllowedMethods($methods);

        $headers = array_change_key_case($this->options["headers.allow"], CASE_LOWER);
        $settings->setAllowedHeaders($headers);

        $settings->setExposedHeaders($this->options["headers.expose"]);

        $settings->setCredentialsNotSupported();
        if($this->options["credentials"]) {
            $settings->setCredentialsSupported();
        }

        if (is_array($this->options["origin.servers"])) {
            $settings->setAllowedOrigins($this->options["origin.servers"]);
        }

        $settings->setPreFlightCacheMaxAge($this->options["cache"]);

        $settings->disableCheckHost();
        if ($this->options["enable.check.host"]) {
            $settings->enableCheckHost();
        }
        $settings->disableAddAllowedMethodsToPreFlightResponse();
        if ($this->options["enable.add.allow.methods.preflight.response"]) {
            $settings->enableAddAllowedMethodsToPreFlightResponse();
        }
        $settings->disableAddAllowedHeadersToPreFlightResponse();
        if ($this->options["enable.add.allow.headers.preflight.response"]) {
            $settings->enableAddAllowedHeadersToPreFlightResponse();
        }

        return $settings;
    }

    private function setOriginSettings(CorsSettings $settings): void
    {
        if($this->options["origin"] === self::ALLOW_ALL_ORIGIN) {
            $settings->enableAllOriginsAllowed();
        }
        $originOptions = parse_url($this->options["origin"]);
        if (!is_array($originOptions)) {
            return;
        }
        $settings->setServerOrigin(
            $originOptions['scheme'] ?? "http",
            $originOptions['host'] ?? "*",
            $originOptions['port'] ?? 80
        );
    }

    /**
     * Set allowed origin.
     */
    private function origin(string $origin): void
    {
        $this->options["origin"] = $origin;
    }

    /**
     * Set request methods to be allowed.
     */
    private function methods($methods): void
    {
        if (is_callable($methods)) {
            if ($methods instanceof Closure) {
                $this->options["methods"] = $methods->bindTo($this);
            } else {
                $this->options["methods"] = $methods;
            }
        } else {
            $this->options["methods"] = (array) $methods;
        }
    }

    /**
     * Set headers to be allowed.
     */
    private function headersAllow(array $headers): void
    {
        $this->options["headers.allow"] = $headers;
    }

    /**
     * Set headers to be exposed.
     */
    private function headersExpose(array $headers): void
    {
        $this->options["headers.expose"] = $headers;
    }

    /**
     * Enable or disable cookies and authentication.
     */
    private function credentials(bool $credentials): void
    {
        $this->options["credentials"] = $credentials;
    }

    /**
     * Set the server origin.
     */
    private function originServers(array $origins): void
    {
        $this->options["origin.servers"] = $origins;
    }

    /**
     * Set the cache time in seconds.
     */
    private function cache(int $cache): void
    {
        $this->options["cache"] = $cache;
    }

    /**
     * Set enable check host
     */
    private function enableCheckHost(bool $value): void
    {
        $this->options['enable.check.host'] = $value;
    }

    /**
     * Set enable check host
     */
    private function enableAddAllowMethodsPreflightResponse(bool $value): void
    {
        $this->options['enable.add.allow.methods.preflight.response'] = $value;
    }

    /**
     * Set enable check host
     */
    private function enableAddAllowHeadersPreflightResponse(bool $value): void
    {
        $this->options['enable.add.allow.headers.preflight.response'] = $value;
    }

    /**
     * Set the error handler.
     */
    private function error(callable $error): void
    {
        if ($error instanceof Closure) {
            $this->options["error"] = $error->bindTo($this);
        } else {
            $this->options["error"] = $error;
        }
    }

    /**
     * Set the PSR-3 logger.
     */
    private function logger(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
    }

    /**
     * Call the error handler if it exists.
     */
    private function processError(ServerRequestInterface $request, ResponseInterface $response, array $arguments = null)
    {
        if (is_callable($this->options["error"])) {
            $handler_response = $this->options["error"]($request, $response, $arguments);
            if (is_a($handler_response, "\Psr\Http\Message\ResponseInterface")) {
                return $handler_response;
            }
        }
        return $response;
    }
}
