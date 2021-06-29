class Config(object):
    '''
    Each environment will be a class that inherits from the main class config
    Configurations that will be the same across all environment will go into config,
    while configuration that are specific to an environment will go into the relevant environment below
    '''
    DEBUG = True
    SECRET_KEY = "YQ2-_wtF~K;S4#nULjV-E@`&Xz@;%Aq81.mn7vWrzF3WJ5P1OvEAf<^(Ov068B"


class Production(Config):
    FLASK_ENV = 'production'
    PRODUCTION = True


class Testing(Config):
    FLASK_ENV = 'testing'
    TESTING = True


class Development(Config):
    FLASK_ENV = 'development'
    DEBUG = True
