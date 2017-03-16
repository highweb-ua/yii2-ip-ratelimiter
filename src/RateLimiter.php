<?php

namespace highweb\ratelimiter;

use Yii;
use yii\base\NotSupportedException;
use highweb\ratelimiter\UserRateLimiterTrait;

class RateLimiter extends \yii\filters\RateLimiter
{
	/**
	 * @var boolean whether to separate rate limiting between non and authenticated users
	 */
	public $separateRates = true;

	/**
	 * @var integer the maximum number of allowed requests
	 */
	public $rateLimit;

	/**
	 * @var integer the time period for the rates to apply to
	 */
	public $timePeriod;

	/**
	 * @inheritdoc
	 */
	public function beforeAction($action)
	{
		$user = $this->user;
		$identityClass = Yii::$app->getUser()->identityClass;
		$userIdentityObject = Yii::createObject($identityClass);

		if ($this->separateRates)
			$user = $user ?: (Yii::$app->getUser() ? Yii::$app->getUser()->getIdentity(false) : null);

		if ($userIdentityObject instanceof UserRateLimiterTrait)
			$user = $user ?: $identityClass::findByIp(Yii::$app->request->userIP, $this->rateLimit, $this->timePeriod);

		if ($user instanceof RateLimitInterface)
		{
			return parent::beforeAction($action);
		}
		else
		{
			Yii::trace('Check rate limit', __METHOD__);
			$this->checkRateLimit(
				$user,
				$this->request ? : Yii::$app->getRequest(),
				$this->response ? : Yii::$app->getResponse(),
				$action
			);

			return true;
		}

		return parent::beforeAction($action);
	}
}
