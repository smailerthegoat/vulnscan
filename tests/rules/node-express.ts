import { Body, Controller, Get, Param, Post, Query } from '@nestjs/common';
import { exec } from 'child_process';
import { NextRequest } from 'next/server';

@Controller('reports')
export class ReportsController {
  constructor(private readonly dataSource: DataSource, private readonly http: HttpService) {}

  @Get()
  async search(@Query('q') q: string, @Query('limit') limit: string) {
    // ruleid: vulnscan.js.sql-injection
    return this.dataSource.query(`SELECT * FROM reports WHERE title LIKE '%${q}%'`);
  }

  @Get(':id')
  async one(@Param('id') id: string) {
    // ok: vulnscan.js.sql-injection
    return this.dataSource.query('SELECT * FROM reports WHERE id = $1', [id]);
  }

  @Post('export')
  async export(@Body() dto: ExportDto) {
    // ruleid: vulnscan.js.command-injection
    exec(`tar czf /tmp/out.tgz ${dto.folder}`);
  }

  internalHelper(name: string) {
    // ok: vulnscan.js.command-injection
    exec(`echo ${name}`);
  }
}

export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get('url');
  // ruleid: vulnscan.js.ssrf
  const r = await fetch(url);
  return new Response(await r.text());
}
