"""
SOC360 Auth Forms
Formulários de autenticação usando Flask-WTF.
"""
import re as _re
from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, BooleanField, SubmitField,
    IntegerField, SelectField,
)
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo,
    ValidationError, Regexp, NumberRange, Optional as WTOptional,
)

# email-validator 2.x rejects reserved TLDs (.local, .internal, etc.) even
# with check_deliverability=False. Use a lenient format-only check for
# authenticated profile forms where any RFC 5322-looking address is OK.
_EMAIL_RE = _re.compile(
    r'^[^@\s]+@[^@\s]+\.[^@\s]+$',
    _re.IGNORECASE,
)


class LenientEmail:
    """WTForms validator: checks only email *format*, not DNS/deliverability.

    Useful for internal addresses such as ``admin@corp.local`` that are
    rejected by ``email-validator 2.x`` despite being syntactically valid.
    """

    def __init__(self, message='E-mail inválido'):
        self.message = message

    def __call__(self, form, field):
        value = (field.data or '').strip()
        if not _EMAIL_RE.match(value):
            raise ValidationError(self.message)


class LoginForm(FlaskForm):
    """Formulário de login."""
    username = StringField(
        'Usuário ou e-mail',
        validators=[
            DataRequired(message='Usuário ou e-mail é obrigatório'),
            Length(min=3, max=255, message='Usuário ou e-mail deve ter entre 3 e 255 caracteres')
        ],
        render_kw={'placeholder': 'Digite seu usuário ou e-mail', 'autocomplete': 'username'}
    )
    
    password = PasswordField(
        'Senha',
        validators=[
            DataRequired(message='Senha é obrigatória')
        ],
        render_kw={'placeholder': 'Digite sua senha', 'autocomplete': 'current-password'}
    )
    
    remember_me = BooleanField('Manter conectado')
    
    submit = SubmitField('Entrar')


class RegisterForm(FlaskForm):
    """Formulário de registro de novos usuários."""
    username = StringField(
        'Usuário',
        validators=[
            DataRequired(message='Usuário é obrigatório'),
            Length(min=3, max=64, message='Usuário deve ter entre 3 e 64 caracteres'),
            Regexp(
                r'^[a-zA-Z0-9_]+$',
                message='Usuário pode conter apenas letras, números e underscore'
            )
        ],
        render_kw={'placeholder': 'Escolha um nome de usuário', 'autocomplete': 'username'}
    )
    
    email = StringField(
        'E-mail',
        validators=[
            DataRequired(message='E-mail é obrigatório'),
            Email(message='E-mail inválido', check_deliverability=False),
            Length(max=255, message='E-mail muito longo')
        ],
        render_kw={'placeholder': 'seu@email.com', 'autocomplete': 'email'}
    )

    password = PasswordField(
        'Senha',
        validators=[
            DataRequired(message='Senha é obrigatória'),
            Length(min=12, message='Senha deve ter no mínimo 12 caracteres')
        ],
        render_kw={'placeholder': 'Mínimo 12 caracteres', 'autocomplete': 'new-password'}
    )

    confirm_password = PasswordField(
        'Confirmar Senha',
        validators=[
            DataRequired(message='Confirmação de senha é obrigatória'),
            EqualTo('password', message='As senhas devem ser iguais')
        ],
        render_kw={'placeholder': 'Repita a senha', 'autocomplete': 'new-password'}
    )

    accept_terms = BooleanField(
        'Li e aceito os Termos de Uso',
        validators=[
            DataRequired(message='Você deve aceitar os termos para continuar')
        ]
    )
    
    submit = SubmitField('Criar Conta')


class InitRootForm(FlaskForm):
    """Formulário para criar primeiro usuário admin (init-root)."""
    username = StringField(
        'Usuário Admin',
        validators=[
            DataRequired(message='Usuário é obrigatório'),
            Length(min=3, max=64, message='Usuário deve ter entre 3 e 64 caracteres'),
            Regexp(
                r'^[a-zA-Z0-9_]+$',
                message='Usuário pode conter apenas letras, números e underscore'
            )
        ],
        render_kw={'placeholder': 'admin', 'autocomplete': 'username'}
    )
    
    email = StringField(
        'E-mail',
        validators=[
            DataRequired(message='E-mail é obrigatório'),
            Email(message='E-mail inválido', check_deliverability=False),
            Length(max=255, message='E-mail muito longo')
        ],
        render_kw={'placeholder': 'admin@empresa.com', 'autocomplete': 'email'}
    )
    
    password = PasswordField(
        'Senha',
        validators=[
            DataRequired(message='Senha é obrigatória'),
            Length(min=12, message='Senha deve ter no mínimo 12 caracteres')
        ],
        render_kw={'placeholder': 'Mínimo 12 caracteres', 'autocomplete': 'new-password'}
    )
    
    confirm_password = PasswordField(
        'Confirmar Senha',
        validators=[
            DataRequired(message='Confirmação de senha é obrigatória'),
            EqualTo('password', message='As senhas devem ser iguais')
        ],
        render_kw={'placeholder': 'Repita a senha', 'autocomplete': 'new-password'}
    )
    
    nvd_api_key = StringField(
        'NVD API Key',
        validators=[
            Length(max=255, message='API Key muito longa')
        ],
        render_kw={'placeholder': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'}
    )
    
    start_sync = BooleanField(
        'Iniciar Sincronização',
        default=True
    )
    
    organization_name = StringField(
        'Nome da Organização',
        validators=[
            Length(max=128, message='Nome muito longo')
        ],
        render_kw={'placeholder': 'Minha Empresa (opcional)'}
    )
    
    submit = SubmitField('Inicializar Sistema')


class PasswordResetForm(FlaskForm):
    """Formulário para redefinir senha."""
    password = PasswordField(
        'Nova Senha',
        validators=[
            DataRequired(message='Senha é obrigatória'),
            Length(min=12, message='Senha deve ter no mínimo 12 caracteres')
        ],
        render_kw={'placeholder': 'Mínimo 12 caracteres', 'autocomplete': 'new-password'}
    )
    
    confirm_password = PasswordField(
        'Confirmar Nova Senha',
        validators=[
            DataRequired(message='Confirmação de senha é obrigatória'),
            EqualTo('password', message='As senhas devem ser iguais')
        ],
        render_kw={'placeholder': 'Repita a nova senha', 'autocomplete': 'new-password'}
    )
    
    submit = SubmitField('Redefinir Senha')


class ChangePasswordForm(FlaskForm):
    """Formulário para alterar senha (usuário logado)."""
    current_password = PasswordField(
        'Senha Atual',
        validators=[
            DataRequired(message='Senha atual é obrigatória')
        ],
        render_kw={'placeholder': 'Digite sua senha atual', 'autocomplete': 'current-password'}
    )
    
    new_password = PasswordField(
        'Nova Senha',
        validators=[
            DataRequired(message='Nova senha é obrigatória'),
            Length(min=12, message='Senha deve ter no mínimo 12 caracteres')
        ],
        render_kw={'placeholder': 'Mínimo 12 caracteres', 'autocomplete': 'new-password'}
    )
    
    confirm_new_password = PasswordField(
        'Confirmar Nova Senha',
        validators=[
            DataRequired(message='Confirmação de senha é obrigatória'),
            EqualTo('new_password', message='As senhas devem ser iguais')
        ],
        render_kw={'placeholder': 'Repita a nova senha', 'autocomplete': 'new-password'}
    )
    
    submit = SubmitField('Alterar Senha')


# Common timezones for the profile form
_TIMEZONES = [
    ('UTC',                  'UTC'),
    ('America/Sao_Paulo',    'Brasil — São Paulo (BRT/BRST)'),
    ('America/Manaus',       'Brasil — Manaus (AMT)'),
    ('America/Belem',        'Brasil — Belém (BRT)'),
    ('America/Fortaleza',    'Brasil — Fortaleza (BRT)'),
    ('America/Recife',       'Brasil — Recife (BRT)'),
    ('America/Cuiaba',       'Brasil — Cuiabá (AMT)'),
    ('America/Porto_Velho',  'Brasil — Porto Velho (AMT)'),
    ('America/Noronha',      'Brasil — Fernando de Noronha (FNT)'),
    ('America/New_York',     'EUA — Nova York (EST/EDT)'),
    ('America/Chicago',      'EUA — Chicago (CST/CDT)'),
    ('America/Denver',       'EUA — Denver (MST/MDT)'),
    ('America/Los_Angeles',  'EUA — Los Angeles (PST/PDT)'),
    ('America/Toronto',      'Canadá — Toronto (EST/EDT)'),
    ('America/Mexico_City',  'México — Cidade do México (CST/CDT)'),
    ('America/Buenos_Aires', 'Argentina — Buenos Aires (ART)'),
    ('America/Santiago',     'Chile — Santiago (CLT/CLST)'),
    ('America/Bogota',       'Colômbia — Bogotá (COT)'),
    ('Europe/London',        'Europa — Londres (GMT/BST)'),
    ('Europe/Lisbon',        'Europa — Lisboa (WET/WEST)'),
    ('Europe/Madrid',        'Europa — Madri (CET/CEST)'),
    ('Europe/Paris',         'Europa — Paris (CET/CEST)'),
    ('Europe/Berlin',        'Europa — Berlim (CET/CEST)'),
    ('Europe/Amsterdam',     'Europa — Amsterdã (CET/CEST)'),
    ('Europe/Moscow',        'Europa — Moscou (MSK)'),
    ('Africa/Luanda',        'África — Luanda (WAT)'),
    ('Africa/Johannesburg',  'África — Joanesburgo (SAST)'),
    ('Asia/Dubai',           'Oriente Médio — Dubai (GST)'),
    ('Asia/Kolkata',         'Índia — Mumbai/Delhi (IST)'),
    ('Asia/Singapore',       'Ásia — Singapura (SGT)'),
    ('Asia/Shanghai',        'Ásia — Xangai/Pequim (CST)'),
    ('Asia/Tokyo',           'Ásia — Tóquio (JST)'),
    ('Asia/Seoul',           'Ásia — Seul (KST)'),
    ('Australia/Sydney',     'Austrália — Sydney (AEST/AEDT)'),
    ('Pacific/Auckland',     'Pacífico — Auckland (NZST/NZDT)'),
]


class ProfileForm(FlaskForm):
    """Formulário para editar perfil do usuário — campos completos."""

    # ── Identidade ──────────────────────────────────────────────────
    username = StringField(
        'Usuário',
        validators=[
            DataRequired(message='Usuário é obrigatório'),
            Length(min=3, max=64, message='Usuário deve ter entre 3 e 64 caracteres'),
            Regexp(
                r'^[a-zA-Z0-9_]+$',
                message='Usuário pode conter apenas letras, números e underscore'
            )
        ],
        render_kw={'placeholder': 'Seu nome de usuário', 'autocomplete': 'username'}
    )

    email = StringField(
        'E-mail',
        validators=[
            DataRequired(message='E-mail é obrigatório'),
            LenientEmail(message='E-mail inválido'),
            Length(max=255, message='E-mail muito longo')
        ],
        render_kw={'placeholder': 'seu@email.com', 'autocomplete': 'email'}
    )

    # ── Perfil pessoal ───────────────────────────────────────────────
    first_name = StringField(
        'Nome',
        validators=[WTOptional(), Length(max=100, message='Nome muito longo')],
        render_kw={'placeholder': 'Seu primeiro nome', 'autocomplete': 'given-name'}
    )

    last_name = StringField(
        'Sobrenome',
        validators=[WTOptional(), Length(max=100, message='Sobrenome muito longo')],
        render_kw={'placeholder': 'Seu sobrenome', 'autocomplete': 'family-name'}
    )

    phone = StringField(
        'Telefone',
        validators=[
            WTOptional(),
            Length(max=20, message='Telefone muito longo'),
            Regexp(r'^[\d\s\+\(\)\-\.]*$', message='Formato de telefone inválido')
        ],
        render_kw={'placeholder': '+55 11 99999-9999', 'autocomplete': 'tel', 'type': 'tel'}
    )

    # ── Organização ──────────────────────────────────────────────────
    department = StringField(
        'Departamento',
        validators=[WTOptional(), Length(max=100, message='Departamento muito longo')],
        render_kw={'placeholder': 'Ex.: TI, Segurança, NOC', 'autocomplete': 'organization-title'}
    )

    job_title = StringField(
        'Cargo',
        validators=[WTOptional(), Length(max=100, message='Cargo muito longo')],
        render_kw={'placeholder': 'Ex.: Analista de Segurança, DevOps', 'autocomplete': 'organization-title'}
    )

    # ── Preferências ─────────────────────────────────────────────────
    timezone = SelectField(
        'Fuso Horário',
        choices=_TIMEZONES,
        default='UTC',
        validators=[WTOptional()]
    )

    submit = SubmitField('Salvar Alterações')


class ApiKeyForm(FlaskForm):
    """Formulário para gerenciar API Key."""
    submit = SubmitField('Gerar Nova API Key')
    revoke = SubmitField('Revogar API Key')


class TacacsConfigForm(FlaskForm):
    """Configuração de autenticação TACACS+ (somente admins).

    O campo ``secret`` é opcional no edit — deixar em branco preserva o
    segredo atual. O formulário é validado condicionalmente: quando
    ``enabled`` é marcado, ``host`` torna-se obrigatório.
    """
    enabled = BooleanField('Habilitar autenticação TACACS+')

    host = StringField(
        'Servidor (host ou IP)',
        # No WTOptional(): it would short-circuit and skip ``validate_host``,
        # which needs to run when ``enabled`` is toggled on with an empty host.
        validators=[
            Length(max=255, message='Host muito longo'),
        ],
        render_kw={'placeholder': 'tacacs.exemplo.com', 'autocomplete': 'off'},
    )

    port = IntegerField(
        'Porta',
        default=49,
        validators=[
            WTOptional(),
            NumberRange(min=1, max=65535, message='Porta deve estar entre 1 e 65535'),
        ],
        render_kw={'placeholder': '49'},
    )

    secret = PasswordField(
        'Shared Secret',
        validators=[
            WTOptional(),
            Length(max=255, message='Segredo muito longo'),
        ],
        render_kw={
            'placeholder': 'Deixe em branco para manter o atual',
            'autocomplete': 'new-password',
        },
    )

    timeout = IntegerField(
        'Timeout (segundos)',
        default=10,
        validators=[
            WTOptional(),
            NumberRange(min=1, max=120, message='Timeout entre 1 e 120 segundos'),
        ],
    )

    auth_type = SelectField(
        'Tipo de autenticação',
        choices=[
            ('ascii', 'ASCII (login interativo)'),
            ('pap',   'PAP (senha em plaintext no envelope criptografado)'),
            ('chap',  'CHAP (challenge-response)'),
        ],
        default='ascii',
    )

    fallback_local = BooleanField(
        'Permitir fallback para autenticação local se TACACS+ falhar',
        default=True,
    )

    auto_create_user = BooleanField(
        'Criar automaticamente usuário local no primeiro login bem-sucedido',
        default=False,
    )

    default_email_domain = StringField(
        'Domínio de e-mail padrão (para auto-criação)',
        validators=[
            WTOptional(),
            Length(max=128),
        ],
        render_kw={'placeholder': 'exemplo.com'},
    )

    # Optional probe credentials for the "Testar Conexão" button
    probe_username = StringField(
        'Usuário para teste (opcional)',
        validators=[WTOptional(), Length(max=80)],
        render_kw={'placeholder': 'Deixe em branco para apenas testar TCP'},
    )
    probe_password = PasswordField(
        'Senha para teste (opcional)',
        validators=[WTOptional(), Length(max=255)],
        render_kw={'autocomplete': 'off'},
    )

    submit_save = SubmitField('Salvar Configuração TACACS+')
    submit_test = SubmitField('Testar Conexão')

    def validate_host(self, field):
        if self.enabled.data and not (field.data or '').strip():
            raise ValidationError('Host é obrigatório quando TACACS+ está habilitado.')

    def validate_default_email_domain(self, field):
        value = (field.data or '').strip()
        if not value:
            return
        # Very light sanity check — a real domain has at least one dot and no '@'
        if '@' in value or '.' not in value:
            raise ValidationError('Informe apenas o domínio, ex.: exemplo.com')
