<?php

namespace Conduction\DigidBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\XmlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class DigidExtension extends Extension
{

    public function load(array $configs, ContainerBuilder $container)
    {
        $this->loadConfig($configs, $container);

        if($container->getParameter('digid_enabled')){
            $loader = new XmlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
            $loader->load('services.xml');
        }
    }

    private function loadConfig(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $processedConfiguration = $this->processConfiguration($configuration, $configs);

        foreach ($processedConfiguration as $key => $value) {
            $container->setParameter(
                'digid.'.$key,
                $value
            );
        }
        $container->setParameter('digid', $processedConfiguration);
    }
}