package rules

// All returns one instance of every rule thorn checks a file against.
func All() []Rule {
	return []Rule{
		AwsAccessKeyID{},
		AwsSecretAccessKey{},
		GenericAPIKey{},
		HardcodedPassword{},
		PrivateKeyBlock{},
		GitHubGitLabToken{},
		DotEnvCommitted{},
		DotEnvProductionCommitted{},
		DockerfileUserRoot{},
		DebugModeEnabled{},
		HardcodedLocalhost{},
	}
}
