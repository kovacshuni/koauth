package com.hunorkovacs.koauth.domain

case class OauthRequest(method: String,
                        urlWithoutParams: String,
                        authorizationHeader: String,
                        urlParams: List[(String, String)],
                        bodyParams: List[(String, String)])

case class EnhancedRequest(method: String,
                           urlWithoutParams: String,
                           urlParams: List[(String, String)],
                           bodyParams: List[(String, String)],
                           oauthParamsList: List[(String, String)],
                           oauthParamsMap: Map[String, String])
