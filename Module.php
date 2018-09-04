<?php
/**
 * This code is licensed under AGPLv3 license or AfterLogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\LdapChangePasswordPlugin;

/**
 * @license https://www.gnu.org/licenses/agpl-3.0.html AGPL-3.0
 * @license https://afterlogic.com/products/common-licensing AfterLogic Software License
 * @copyright Copyright (c) 2018, Afterlogic Corp.
 *
 * @package Modules
 */
class Module extends \Aurora\System\Module\AbstractModule
{
	/**
	 * @param CApiPluginManager $oPluginManager
	 */
	
	public function init() 
	{
		$this->oMailModule = \Aurora\System\Api::GetModule('Mail');
	
		$this->subscribeEvent('Mail::ChangePassword::before', array($this, 'onBeforeChangePassword'));
	}
	
	/**
	 * @staticvar CLdapConnector|null $oLdap
	 * @param CAccount $oAccount
	 * @return \Aurora\System\Utils\Ldap|bool
	 */
	private function GetLdap($oAccount, $sDn, $sPassword)
	{
		if (!$oAccount)
		{
			return false;
		}

		$oLdap = new \Aurora\System\Utils\Ldap((string)$this->getConfig('SearchDn', ''));
		return $oLdap->Connect(
			(string) $this->getConfig('Host', '127.0.0.1'),
			(int) $this->getConfig('Port', 389),
			(string) $sDn,
			(string) $sPassword,
			(string) $this->getConfig('HostBackup', ''),
			(int) $this->getConfig('PortBackup', 389)
		) ? $oLdap : false;
	}
	
	function PasswordHash($sPassword)
	{
		$sEncType = strtolower((string)  $this->getConfig('PasswordType', 'clear'));

		$sPasswordHash = '';
		switch($sEncType)
		{
			case 'clear':
				$sPasswordHash = $sPassword;
				break;
			case 'md5':
				$sMd5Hash = md5($sPassword);
				for ( $i = 0; $i < 32; $i += 2 )
				{
					$sPasswordHash .= chr( hexdec( $sMd5Hash{ $i + 1 } ) + hexdec( $sMd5Hash{ $i } ) * 16 );
				}
				$sPasswordHash = '{MD5}'.base64_encode($sPasswordHash);
				break;
			case 'crypt':
			default:
				$sPasswordHash = '{CRYPT}'.crypt($sPassword);
				break;
		}

		return $sPasswordHash;
	}		

	/**
	 * @param CAccount $oAccount
	 */
	public function changePassword($oAccount, $sPassword)
	{
	    $bResult = false;
	    if (0 < strlen($oAccount->IncomingPassword) && $oAccount->IncomingPassword !== $sPassword )
	    {
			$oLdap = $this->GetLdap($oAccount, $this->getConfig('BindDn', ''), $this->getConfig('BindPassword', ''));

			$sSearchAttribute = (string) $this->getConfig('SearchAttribute', 'mail');
			
			if ($oLdap)
			{
				
				if($oLdap->Search('('. $sSearchAttribute .'='.$oAccount->Email.')') && 1 === $oLdap->ResultCount())
				{
					$aData = $oLdap->ResultItem();
					$sDn = !empty($aData['dn']) ? $aData['dn'] : '';

					try
					{
						if (!empty($sDn) && $this->GetLdap($oAccount, $sDn, $oAccount->IncomingPassword))
						{
							$aModifyEntry = array(
								(string) $this->getConfig('PasswordAttribute', 'password') => $this->PasswordHash($sPassword)
							);
							$oLdap->SetSearchDN('');
							$oLdap->Modify($sDn, $aModifyEntry);
							$bResult = true;
						}
						else
						{
							\Aurora\System\Api::Log('Can`t change password for user ' . $oAccount->Email . ' on LDAP-server', \Aurora\System\Enums\LogLevel::Full, 'ldap-');
						}
					}
					catch (\Exception $oException)
					{
						$bResult = false;
						\Aurora\System\Api::LogException($oException, \Aurora\System\Enums\LogLevel::Full, 'ldap-');
					}
				}
				else
				{
					$bResult = false;
					\Aurora\System\Api::Log('Can`t find user ' . $oAccount->Email . ' on LDAP-server', \Aurora\System\Enums\LogLevel::Full, 'ldap-');
				}
			}
			else
			{
				\Aurora\System\Api::Log('Can`t connect to LDAP-server', \Aurora\System\Enums\LogLevel::Full, 'ldap-');
			}
		}
		
		return $bResult;
	}
	
	/**
	 * 
	 * @param array $aArguments
	 * @param mixed $mResult
	 */
	public function onBeforeChangePassword($aArguments, &$mResult)
	{
		$mResult = true;
		
		$oAccount = $this->oMailModule->GetAccount($aArguments['AccountId']);

		if ($oAccount)
		{
			if ($this->checkCanChangePassword($oAccount))
			{
				$mResult = $this->changePassword($oAccount, $aArguments['NewPassword']);
				return !$mResult; // break subscriptions
			}
			else
			{
				\Aurora\System\Api::Log('Change password is not allowed for this account', \Aurora\System\Enums\LogLevel::Full, 'ldap-');
			}
		}
		else
		{
			\Aurora\System\Api::Log('Account not found', \Aurora\System\Enums\LogLevel::Full, 'ldap-');
		}
			
	}

	/**
	 * @param CAccount $oAccount
	 * @return bool
	 */
	protected function checkCanChangePassword($oAccount)
	{
		$bFound = in_array("*", $this->getConfig('SupportedServers', array()));
		
		if (!$bFound)
		{
			$oServer = $this->oMailModule->GetServer($oAccount->ServerId);
			if ($oServer && in_array($oServer->Name, $this->getConfig('SupportedServers')))
			{
				$bFound = true;
			}
		}
		return $bFound;
	}
	
	public function loadModuleSettings()
	{
		return parent::loadModuleSettings();
	}	
	
}