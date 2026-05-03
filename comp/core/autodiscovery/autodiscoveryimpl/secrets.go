// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package autodiscoveryimpl

import (
	"fmt"
	"strconv"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	secrets "github.com/DataDog/datadog-agent/comp/core/secrets/def"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func decryptConfig(conf integration.Config, secretResolver secrets.Component) (integration.Config, error) {
	if pkgconfigsetup.Datadog().GetBool("secret_backend_skip_checks") {
		log.Tracef("'secret_backend_skip_checks' is enabled, not decrypting configuration %q", conf.Name)
		return conf, nil
	}

	var err error

	// init_config is shared by all instances — any failure drops the entire config.
	conf.InitConfig, err = secretResolver.Resolve(conf.InitConfig, conf.Name, conf.ImageName, conf.PodNamespace, false)
	if err != nil {
		return conf, fmt.Errorf("error while decrypting secrets in 'init_config': %s", err)
	}

	// instances — failing instances are skipped so surviving ones are still scheduled.
	// Each instance uses a temporary per-index origin (e.g. "http_check/0") that callers
	// rename to the actual check instance ID once the fully-decrypted config is available.
	var instanceErr error
	instances := make([]integration.Data, 0, len(conf.Instances))
	for i, inputInstance := range conf.Instances {
		instanceOrigin := conf.Name + "/" + strconv.Itoa(i)
		decryptedInstance, err := secretResolver.Resolve(inputInstance, instanceOrigin, conf.ImageName, conf.PodNamespace, false)
		if err != nil {
			instanceErr = fmt.Errorf("error while decrypting secrets in an instance: %s", err)
			continue
		}
		instances = append(instances, decryptedInstance)
	}
	conf.Instances = instances

	// metrics
	conf.MetricConfig, err = secretResolver.Resolve(conf.MetricConfig, conf.Name, conf.ImageName, conf.PodNamespace, false)
	if err != nil {
		return conf, fmt.Errorf("error while decrypting secrets in 'metrics': %s", err)
	}

	// logs
	conf.LogsConfig, err = secretResolver.Resolve(conf.LogsConfig, conf.Name, conf.ImageName, conf.PodNamespace, false)
	if err != nil {
		return conf, fmt.Errorf("error while decrypting secrets in 'logs': %s", err)
	}

	return conf, instanceErr
}
