<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\LdapChangePasswordPlugin;

use Aurora\System\SettingsProperty;

/**
 * @property bool $Disabled"
 * @property array $SupportedServers"
 * @property string $SearchDn"
 * @property string $Host"
 * @property int $Port"
 * @property string $BindDn"
 * @property string $BindPassword"
 * @property string $HostBackup"
 * @property int $PortBackup"
 * @property string $PasswordType"
 * @property string $SearchAttribute"
 * @property string $PasswordAttribute"
 */

class Settings extends \Aurora\System\Module\Settings
{
    protected function initDefaults()
    {
        $this->aContainer = [
            "Disabled" => new SettingsProperty(
                false,
                "bool",
                null,
                ""
            ),
            "SupportedServers" => new SettingsProperty(
                ["*"],
                "array",
                null,
                ""
            ),
            "SearchDn" => new SettingsProperty(
                "ou=Users,dc=afterlogic,dc=com",
                "string",
                null,
                ""
            ),
            "Host" => new SettingsProperty(
                "127.0.0.1",
                "string",
                null,
                ""
            ),
            "Port" => new SettingsProperty(
                389,
                "int",
                null,
                ""
            ),
            "BindDn" => new SettingsProperty(
                "cn=Administrator,dc=afterlogic,dc=com",
                "string",
                null,
                ""
            ),
            "BindPassword" => new SettingsProperty(
                "secret",
                "string",
                null,
                ""
            ),
            "HostBackup" => new SettingsProperty(
                "",
                "string",
                null,
                ""
            ),
            "PortBackup" => new SettingsProperty(
                389,
                "int",
                null,
                ""
            ),
            "PasswordType" => new SettingsProperty(
                "clear",
                "string",
                null,
                ""
            ),
            "SearchAttribute" => new SettingsProperty(
                "mail",
                "string",
                null,
                ""
            ),
            "PasswordAttribute" => new SettingsProperty(
                "userPassword",
                "string",
                null,
                ""
            ),
        ];
    }
}
