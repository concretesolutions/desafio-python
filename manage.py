from flask_script import (
    Command,
    Manager
)
from flask_migrate import (
    Migrate,
    MigrateCommand
)

from user_api import (
    user_api_app,
    db
)
from user_api import models


migrate = Migrate(user_api_app, db)
manager = Manager(user_api_app)
manager.add_command('db', MigrateCommand)


@manager.command
def recreate_database():
    "Recreate database"
    db.drop_all()
    db.create_all()


if __name__ == "__main__":
    manager.run()
