package com.hunorkovacs.koauth.service

trait Verification

trait VerificationNok extends Verification

case object VerificationOk extends Verification

case object VerificationUnsupported extends VerificationNok

case object VerificationFailed extends VerificationNok
