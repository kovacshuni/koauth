package com.hunorkovacs.koauth.service

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.service.OauthService.RequestTokenResources
import com.hunorkovacs.koauth.domain.{OauthParams, Rights}

trait OauthPersistence {

  def persistRequestToken(requestTokenResourcesF: Future[RequestTokenResources])
                         (implicit ec: ExecutionContext): Future[Unit]

  def getRights(requestTokenF: Future[String])
               (implicit ec: ExecutionContext): Future[Rights]

  def authenticate(usernameF: Future[String], passwordF: Future[String])
                  (implicit ec: ExecutionContext): Future[Unit]

  def authorize(consumerKeyF: Future[String], tokenF: Future[String],
                usernameF: Future[String], verifierF: Future[String])
               (implicit ec: ExecutionContext): Future[Unit]

  def whoAuthorizedRequestToken(consumerKeyF: Future[String], tokenF: Future[String],
                               verifierF: Future[String])
                              (implicit ec: ExecutionContext): Future[(String, Rights)]

  def persistAccessToken(consumerKeyF: Future[String], consumerSecretF: Future[String],
                         tokenF: Future[String], tokenSecretF: Future[String],
                         rightsF: Future[Rights], usernameF: Future[String])
                         (implicit ec: ExecutionContext): Future[Unit]

  def getToken(consumerKeyF: Future[String], tokenF: Future[String])
                        (implicit ec: ExecutionContext): Future[(String, String, String, Rights)]
}
