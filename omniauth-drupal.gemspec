# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-drupal/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-drupal"
  spec.version       = Omniauth::Drupal::VERSION
  spec.authors       = ["Eugene Correia"]
  spec.email         = ["ecorreia@blueskybroadcast.com"]
  spec.summary       = %q{Drupal Omniauth Gem}
  spec.description   = %q{Drupal Ominauth gem using oauth2 specs}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency 'omniauth', '~> 1.0'
  spec.add_dependency 'omniauth-oauth2', '~> 1.0'
  spec.add_dependency 'typhoeus'

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
end
